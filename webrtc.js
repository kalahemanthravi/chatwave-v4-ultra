// ChatWave 4.0 Hybrid WebRTC Engine (Firebase Firestore + Supabase Realtime Signaling)
// Based on NexCall WebRTC & P2P Engine with Dual-Engine Signaling

import {
  collection,
  doc,
  setDoc,
  getDoc,
  updateDoc,
  onSnapshot,
  serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

// STUN configuration
const peerConfiguration = {
  iceServers: [
    {
      urls: [
        'stun:stun.l.google.com:19302',
        'stun:stun1.l.google.com:19302',
        'stun:stun2.l.google.com:19302'
      ],
    },
  ],
  iceCandidatePoolSize: 10,
};

// Database references injected via initWebRTC
let db = null;
let supabase = null;

// State variables
let localStream = null;
let remoteStream = null;
let peerConnection = null;
let currentCallId = null;
let dataChannel = null;
let activeCallChannel = null;

// Firebase listeners for cleanup
let callDocListener = null;

// Callbacks to UI (app.js)
let uiCallbacks = {
  onCallAccepted: () => { },
  onCallEnded: () => { },
  onRemoteStream: () => { },
  onChatMessage: () => { },
  onError: () => { }
};

/**
 * Initialize WebRTC with Firestore & Supabase instances
 */
export function initWebRTC(instances) {
  db = instances.db;
  supabase = instances.supabase;
}

/**
 * Register UI callback handlers
 */
export function registerCallbacks(callbacks) {
  uiCallbacks = { ...uiCallbacks, ...callbacks };
}

/**
 * Initialize WebRTC connection with local camera and microphone
 */
async function initializeMedia(callType = "video") {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({
      video: callType === "video" ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: "user" } : false,
      audio: { echoCancellation: true, noiseSuppression: true }
    });
    remoteStream = new MediaStream();
    return { localStream, remoteStream };
  } catch (err) {
    console.error("Error accessing media devices:", err);
    uiCallbacks.onError("Could not access camera/microphone. Please verify device permissions.");
    throw err;
  }
}

/**
 * Setup RTCPeerConnection and add local tracks
 */
function setupPeerConnection() {
  peerConnection = new RTCPeerConnection(peerConfiguration);

  // Add local tracks to peer connection
  if (localStream) {
    localStream.getTracks().forEach((track) => {
      peerConnection.addTrack(track, localStream);
    });
  }

  // Listen for remote tracks
  peerConnection.ontrack = (event) => {
    if (event.streams && event.streams[0]) {
      event.streams[0].getTracks().forEach((track) => {
        remoteStream.addTrack(track);
      });
    } else if (event.track) {
      remoteStream.addTrack(event.track);
    }
    uiCallbacks.onRemoteStream(remoteStream);
  };
}

/**
 * Setup E2EE Data Channel for in-call data
 */
function setupDataChannel(channel) {
  channel.onmessage = (event) => {
    try {
      const messageData = JSON.parse(event.data);
      uiCallbacks.onChatMessage(messageData);
    } catch (err) {
      console.error("Failed to parse incoming chat message", err);
    }
  };
}

/**
 * Initiates an outgoing call using Dual Signaling (Firebase + Supabase)
 */
export async function startCall(callerUser, calleeUser, callType = "video") {
  try {
    const media = await initializeMedia(callType);
    setupPeerConnection();

    // Create Data Channel
    dataChannel = peerConnection.createDataChannel("chat");
    setupDataChannel(dataChannel);

    // Create Call document in Firestore
    const callRef = doc(collection(db, "calls"));
    currentCallId = callRef.id;

    // Create SDP Offer
    const offerDescription = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offerDescription);

    // Wait for ICE candidate gathering to finish completely (Bulk ICE pattern from NexCall)
    if (peerConnection.iceGatheringState !== "complete") {
      await new Promise((resolve) => {
        const checkState = () => {
          if (peerConnection.iceGatheringState === "complete") {
            peerConnection.removeEventListener("icegatheringstatechange", checkState);
            resolve();
          }
        };
        peerConnection.addEventListener("icegatheringstatechange", checkState);
        // Safety timeout of 2.5s
        setTimeout(() => {
          peerConnection.removeEventListener("icegatheringstatechange", checkState);
          resolve();
        }, 2500);
      });
    }

    const offer = {
      sdp: peerConnection.localDescription.sdp,
      type: peerConnection.localDescription.type,
    };

    const callPayload = {
      callId: currentCallId,
      callerId: callerUser.uid,
      callerName: callerUser.displayName || callerUser.name || callerUser.email?.split("@")[0] || "User",
      callerEmail: callerUser.email || "",
      callerPhotoURL: callerUser.photoURL || "",
      calleeId: calleeUser.id || calleeUser.uid,
      calleeName: calleeUser.name || calleeUser.displayName || calleeUser.email?.split("@")[0] || "User",
      calleeEmail: calleeUser.email || "",
      offer: offer,
      status: "ringing",
      callType: callType,
      createdAt: serverTimestamp()
    };

    // 1. Write Call metadata to Firestore RTDB
    await setDoc(callRef, callPayload);

    // 2. Broadcast call-invite over Supabase Realtime channel for zero-latency alert
    if (supabase) {
      activeCallChannel = supabase.channel(`call-session:${currentCallId}`, {
        config: { broadcast: { self: false } }
      });

      activeCallChannel
        .on('broadcast', { event: 'call-signal' }, async ({ payload }) => {
          if (!payload) return;
          if (payload.type === 'answer' && !peerConnection.currentRemoteDescription && payload.answer) {
            try {
              const answerDescription = new RTCSessionDescription(payload.answer);
              await peerConnection.setRemoteDescription(answerDescription);
              uiCallbacks.onCallAccepted();
            } catch (e) {
              console.warn("Supabase answer error:", e);
            }
          }
          if (payload.type === 'hangup' || payload.type === 'decline') {
            cleanUpCall();
            uiCallbacks.onCallEnded(payload.type === 'decline' ? 'declined' : 'ended');
          }
        })
        .subscribe();

      // Broadcast to callee's personal notification channel
      const calleeSignalChannel = supabase.channel(`user-call:${calleeUser.id || calleeUser.uid}`);
      calleeSignalChannel.subscribe((status) => {
        if (status === 'SUBSCRIBED') {
          calleeSignalChannel.send({
            type: 'broadcast',
            event: 'incoming-call',
            payload: {
              ...callPayload,
              createdAt: Date.now()
            }
          });
        }
      });
    }

    // 3. Listen to changes in the Firestore call document (waiting for answers or hang up)
    callDocListener = onSnapshot(callRef, async (snapshot) => {
      const data = snapshot.data();
      if (!data) return;

      // Handle call accepted
      if (data.status === "accepted" && !peerConnection?.currentRemoteDescription && data.answer) {
        try {
          const answerDescription = new RTCSessionDescription(data.answer);
          await peerConnection.setRemoteDescription(answerDescription);
          uiCallbacks.onCallAccepted();
        } catch (e) {
          console.warn("Firestore answer error:", e);
        }
      }

      // Handle call rejected/declined
      if (data.status === "declined" || data.status === "ended") {
        cleanUpCall();
        uiCallbacks.onCallEnded(data.status);
      }
    });

    return currentCallId;
  } catch (err) {
    console.error("Error starting call:", err);
    cleanUpCall();
    throw err;
  }
}

/**
 * Accepts an incoming call using Dual Signaling (Firebase + Supabase)
 */
export async function acceptCall(callId, currentUserId) {
  try {
    currentCallId = callId;

    const callRef = doc(db, "calls", callId);
    const callDoc = await getDoc(callRef);
    if (!callDoc.exists()) throw new Error("Call session not found.");

    const callData = callDoc.data();
    const callType = callData.callType || "video";

    const media = await initializeMedia(callType);
    setupPeerConnection();

    // Listen for Data Channel from caller
    peerConnection.ondatachannel = (event) => {
      dataChannel = event.channel;
      setupDataChannel(dataChannel);
    };

    // Set Remote description to Caller's Offer
    const offerDescription = new RTCSessionDescription(callData.offer);
    await peerConnection.setRemoteDescription(offerDescription);

    // Create SDP Answer
    const answerDescription = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answerDescription);

    // Wait for ICE candidate gathering to finish completely (Bulk ICE)
    if (peerConnection.iceGatheringState !== "complete") {
      await new Promise((resolve) => {
        const checkState = () => {
          if (peerConnection.iceGatheringState === "complete") {
            peerConnection.removeEventListener("icegatheringstatechange", checkState);
            resolve();
          }
        };
        peerConnection.addEventListener("icegatheringstatechange", checkState);
        setTimeout(() => {
          peerConnection.removeEventListener("icegatheringstatechange", checkState);
          resolve();
        }, 2500);
      });
    }

    const answer = {
      sdp: peerConnection.localDescription.sdp,
      type: peerConnection.localDescription.type,
    };

    // 1. Write answer and status back to Firestore call document
    await updateDoc(callRef, {
      answer: answer,
      status: "accepted"
    });

    // 2. Broadcast answer over Supabase Realtime channel
    if (supabase) {
      if (!activeCallChannel) {
        activeCallChannel = supabase.channel(`call-session:${callId}`, {
          config: { broadcast: { self: false } }
        });
      }
      activeCallChannel
        .on('broadcast', { event: 'call-signal' }, (payload) => {
          if (payload?.type === 'hangup') {
            cleanUpCall();
            uiCallbacks.onCallEnded("ended");
          }
        })
        .subscribe((status) => {
          if (status === 'SUBSCRIBED') {
            activeCallChannel.send({
              type: 'broadcast',
              event: 'call-signal',
              payload: { type: 'answer', answer }
            });
          }
        });
    }

    // 3. Listen to changes in the call document (listening for hang up)
    callDocListener = onSnapshot(callRef, (snapshot) => {
      const data = snapshot.data();
      if (!data) return;

      if (data.status === "ended") {
        cleanUpCall();
        uiCallbacks.onCallEnded("ended");
      }
    });

    return {
      localStream,
      remoteStream,
      callType,
      callerPhotoURL: callData.callerPhotoURL || null,
      callerName: callData.callerName || "User"
    };
  } catch (err) {
    console.error("Error accepting call:", err);
    cleanUpCall();
    throw err;
  }
}

/**
 * Declines an incoming call
 */
export async function declineCall(callId) {
  try {
    if (supabase) {
      const channel = supabase.channel(`call-session:${callId}`);
      channel.subscribe((status) => {
        if (status === 'SUBSCRIBED') {
          channel.send({
            type: 'broadcast',
            event: 'call-signal',
            payload: { type: 'decline' }
          });
        }
      });
    }
    const callRef = doc(db, "calls", callId);
    await updateDoc(callRef, { status: "declined" });
  } catch (err) {
    console.error("Error declining call:", err);
  }
}

/**
 * Cancels or terminates the active call
 */
export async function hangUpCall(duration = null) {
  if (!currentCallId) {
    cleanUpCall();
    return;
  }
  try {
    if (supabase && activeCallChannel) {
      activeCallChannel.send({
        type: 'broadcast',
        event: 'call-signal',
        payload: { type: 'hangup' }
      });
    }
    const callRef = doc(db, "calls", currentCallId);
    const updates = { status: "ended" };
    if (duration !== null) {
      updates.duration = duration;
    }
    await updateDoc(callRef, updates);
  } catch (err) {
    console.error("Error hanging up call:", err);
  } finally {
    cleanUpCall();
  }
}

/**
 * Mutes or unmutes local microphone track
 */
export function toggleAudio(mute) {
  if (localStream) {
    localStream.getAudioTracks().forEach(track => {
      track.enabled = !mute;
    });
  }
}

/**
 * Enables or disables local camera feed
 */
export function toggleVideo(disable) {
  if (localStream) {
    localStream.getVideoTracks().forEach(track => {
      track.enabled = !disable;
    });
  }
}

/**
 * Screen Sharing Implementation
 */
export async function toggleScreenShare(enable, onStopCallback) {
  if (!peerConnection) return null;
  try {
    if (enable) {
      const screenStream = await navigator.mediaDevices.getDisplayMedia({
        video: true
      });
      const videoTrack = screenStream.getVideoTracks()[0];

      // Replace the video track in peer connection
      const senders = peerConnection.getSenders();
      const sender = senders.find(s => s.track && s.track.kind === 'video');
      if (sender) {
        sender.replaceTrack(videoTrack);
      }

      // Automatically handle screen sharing stop button of the browser
      videoTrack.onended = () => {
        toggleScreenShare(false, onStopCallback);
        if (onStopCallback) onStopCallback();
      };

      return screenStream;
    } else {
      // Revert back to camera stream
      const videoTrack = localStream ? localStream.getVideoTracks()[0] : null;
      const senders = peerConnection.getSenders();
      const sender = senders.find(s => s.track && s.track.kind === 'video');
      if (sender && videoTrack) {
        sender.replaceTrack(videoTrack);
      }
      return null;
    }
  } catch (err) {
    console.error("Screen share failed:", err);
    throw err;
  }
}

/**
 * Clean up local streams, peer connections, and listeners
 */
export function cleanUpCall() {
  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localStream = null;
  }
  remoteStream = null;

  if (peerConnection) {
    peerConnection.close();
    peerConnection = null;
  }

  if (callDocListener) {
    callDocListener();
    callDocListener = null;
  }

  if (activeCallChannel) {
    activeCallChannel.unsubscribe();
    activeCallChannel = null;
  }

  if (dataChannel) {
    dataChannel.close();
    dataChannel = null;
  }

  currentCallId = null;
}

/**
 * Returns the active local stream
 */
export function getLocalStream() {
  return localStream;
}
