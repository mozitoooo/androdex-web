const STORAGE_KEYS = {
  identity: "androdex.web.identity",
  trustedHosts: "androdex.web.trustedHosts",
  relaySession: "androdex.web.relaySession",
  lastAppliedHostSeq: "androdex.web.lastAppliedHostSeq",
};

const PROTOCOL_VERSION = 1;
const PAIRING_QR_VERSION = 1;
const HANDSHAKE_TAG = "androdex-e2ee-v1";
const TRUSTED_RESOLVE_TAG = "androdex-trusted-session-resolve-v1";

const els = {
  statusText: document.getElementById("statusText"),
  errorText: document.getElementById("errorText"),
  pairingPayloadInput: document.getElementById("pairingPayloadInput"),
  pairingCodeInput: document.getElementById("pairingCodeInput"),
  startScannerBtn: document.getElementById("startScannerBtn"),
  stopScannerBtn: document.getElementById("stopScannerBtn"),
  pairConnectBtn: document.getElementById("pairConnectBtn"),
  connectSavedBtn: document.getElementById("connectSavedBtn"),
  resolveTrustedBtn: document.getElementById("resolveTrustedBtn"),
  disconnectBtn: document.getElementById("disconnectBtn"),
  threadIdInput: document.getElementById("threadIdInput"),
  promptInput: document.getElementById("promptInput"),
  sendPromptBtn: document.getElementById("sendPromptBtn"),
  approvalList: document.getElementById("approvalList"),
  eventLog: document.getElementById("eventLog"),
  qrVideo: document.getElementById("qrVideo"),
  scannerHint: document.getElementById("scannerHint"),
};

const state = {
  identity: null,
  trustedHosts: {},
  relaySession: null,
  connectionState: "not_paired",
  lastError: "",
  ws: null,
  pendingHandshake: null,
  secureSession: null,
  approvals: [],
  scannerStream: null,
  scannerTimer: null,
  scannerDetector: null,
  bootstrapped: false,
  codexInitialized: false,
  initializingPromise: null,
  pendingRpc: new Map(),
  activeThreadId: "",
};

const bootstrapPromise = bootstrap().catch((error) => {
  const message = `Initialization failed: ${error.message}`;
  setError(message);
  logEvent(message);
});

window.addEventListener("error", (event) => {
  const message = event?.error?.message || event?.message || "Unknown page error.";
  setError(`App error: ${message}`);
  logEvent(`App error: ${message}`);
});

window.addEventListener("unhandledrejection", (event) => {
  const reason = event?.reason;
  const message = reason?.message || String(reason || "Unknown promise rejection.");
  setError(`App error: ${message}`);
  logEvent(`Unhandled rejection: ${message}`);
});

els.startScannerBtn.addEventListener("click", () => startQrScanner());
els.stopScannerBtn.addEventListener("click", () => stopQrScanner());
els.pairConnectBtn.addEventListener("click", () => pairAndConnect());
els.connectSavedBtn.addEventListener("click", () => connectSavedSession());
els.resolveTrustedBtn.addEventListener("click", () => resolveTrustedAndConnect());
els.disconnectBtn.addEventListener("click", () => disconnectSocket());
els.sendPromptBtn.addEventListener("click", () => sendPrompt());

async function bootstrap() {
  await ensureCryptoSupport();
  state.identity = await loadOrCreateIdentity();
  state.trustedHosts = loadTrustedHosts();
  state.relaySession = loadRelaySession();
  els.threadIdInput.value = "";
  if (state.relaySession) {
    setConnectionState("trusted_host");
    logEvent(`Loaded saved session for host ${shortId(state.relaySession.hostDeviceId)}.`);
  } else {
    setConnectionState("not_paired");
  }
  refreshScannerAvailabilityHint();
  maybeRegisterServiceWorker();
  state.bootstrapped = true;
  logEvent("Web client initialized.");
}

function maybeRegisterServiceWorker() {
  if (!("serviceWorker" in navigator)) {
    return;
  }
  if (!window.isSecureContext && !location.hostname.includes("localhost") && location.protocol !== "http:") {
    return;
  }
  navigator.serviceWorker.register("./sw.js").catch(() => {
    // best effort
  });
}

async function pairAndConnect() {
  logEvent("Pair + Connect pressed.");
  try {
    await bootstrapPromise;
    ensureInitialized();

    const rawPayload = (els.pairingPayloadInput.value || "").trim();
    const pairingCode = (els.pairingCodeInput.value || "").trim();
    if (!rawPayload) {
      return setError("Paste or scan a pairing payload first.");
    }
    if (!pairingCode) {
      return setError("Enter the one-time pairing code from the laptop.");
    }

    const payload = parsePairingPayload(rawPayload);
    if (!payload.ok) {
      return setError(payload.error);
    }

    saveRelaySession({
      relay: payload.value.relay,
      sessionId: payload.value.sessionId,
      hostDeviceId: payload.value.hostDeviceId,
      hostIdentityPublicKey: payload.value.hostIdentityPublicKey,
    });

    await connectToRelay({
      relay: payload.value.relay,
      sessionId: payload.value.sessionId,
      hostDeviceId: payload.value.hostDeviceId,
      hostIdentityPublicKey: payload.value.hostIdentityPublicKey,
      mode: "qr_bootstrap",
      pairingCode,
    });
  } catch (error) {
    setError(`Pairing failed: ${error.message}`);
  }
}

async function connectSavedSession() {
  try {
    await bootstrapPromise;
    ensureInitialized();
    if (!state.relaySession) {
      return setError("No saved session found. Pair first.");
    }

    await connectToRelay({
      relay: state.relaySession.relay,
      sessionId: state.relaySession.sessionId,
      hostDeviceId: state.relaySession.hostDeviceId,
      hostIdentityPublicKey: state.relaySession.hostIdentityPublicKey,
      mode: "trusted_reconnect",
      pairingCode: "",
    });
  } catch (error) {
    setError(`Connect failed: ${error.message}`);
  }
}

async function resolveTrustedAndConnect() {
  await bootstrapPromise;
  ensureInitialized();
  const preferredHost = preferredTrustedHost();
  if (!preferredHost) {
    return setError("No trusted host found yet. Pair first.");
  }
  setConnectionState("resolving_trusted");

  try {
    const nonce = crypto.randomUUID();
    const timestamp = Date.now();
    const transcript = concatBytes(
      encodeUtf8LP(TRUSTED_RESOLVE_TAG),
      encodeUtf8LP(preferredHost.hostDeviceId),
      encodeUtf8LP(state.identity.androidDeviceId),
      encodeDataLP(base64ToBytes(state.identity.androidIdentityPublicKey)),
      encodeUtf8LP(nonce),
      encodeUtf8LP(String(timestamp))
    );

    const identityPrivateKey = await importEd25519PrivateKey(state.identity.androidIdentityPrivateKey);
    const signatureBuffer = await crypto.subtle.sign("Ed25519", identityPrivateKey, transcript);
    const signature = bytesToBase64(new Uint8Array(signatureBuffer));

    const endpoint = trustedResolveEndpoint(preferredHost.relayUrl);
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        hostDeviceId: preferredHost.hostDeviceId,
        androidDeviceId: state.identity.androidDeviceId,
        androidIdentityPublicKey: state.identity.androidIdentityPublicKey,
        nonce,
        timestamp,
        signature,
      }),
    });
    const body = await response.json();
    if (!response.ok || !body.ok) {
      throw new Error(body.error || body.message || "Trusted resolve failed.");
    }

    const session = {
      relay: preferredHost.relayUrl,
      sessionId: body.sessionId,
      hostDeviceId: body.hostDeviceId,
      hostIdentityPublicKey: body.hostIdentityPublicKey,
    };
    saveRelaySession(session);
    await connectToRelay({
      ...session,
      mode: "trusted_reconnect",
      pairingCode: "",
    });
  } catch (error) {
    setError(`Trusted resolve failed: ${error.message}`);
    setConnectionState("trusted_host");
  }
}

async function connectToRelay({
  relay,
  sessionId,
  hostDeviceId,
  hostIdentityPublicKey,
  mode,
  pairingCode,
}) {
  clearError();
  disconnectSocket();

  const wsUrl = relayWebSocketUrl(relay, sessionId);
  setConnectionState(mode === "trusted_reconnect" ? "reconnecting" : "handshaking");
  logEvent(`Connecting to ${wsUrl}`);

  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephemeralPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const clientNonce = randomBytes(32);

  const pending = {
    mode,
    relay,
    sessionId,
    hostDeviceId,
    hostIdentityPublicKey,
    pairingCode,
    ephemeralPrivateKey: ephemeral.privateKey,
    ephemeralPublicRaw,
    clientNonce,
  };
  state.pendingHandshake = pending;

  const socket = new WebSocket(wsUrl);
  state.ws = socket;

  socket.addEventListener("open", () => {
    const clientHello = {
      kind: "clientHello",
      protocolVersion: PROTOCOL_VERSION,
      sessionId: pending.sessionId,
      handshakeMode: pending.mode,
      androidDeviceId: state.identity.androidDeviceId,
      androidIdentityPublicKey: state.identity.androidIdentityPublicKey,
      androidEphemeralPublicKey: bytesToBase64(pending.ephemeralPublicRaw),
      clientNonce: bytesToBase64(pending.clientNonce),
      pairingCode: pending.mode === "qr_bootstrap" ? pending.pairingCode : undefined,
    };
    socket.send(JSON.stringify(clientHello));
    logEvent("Sent clientHello");
  });

  socket.addEventListener("message", async (event) => {
    const text = typeof event.data === "string" ? event.data : "";
    if (!text) {
      return;
    }
    await handleWireMessage(text);
  });

  socket.addEventListener("close", (event) => {
    const closeCode = Number(event?.code) || 1000;
    const closeReason = String(event?.reason || "");
    state.ws = null;
    state.pendingHandshake = null;
    state.secureSession = null;
    state.codexInitialized = false;
    state.activeThreadId = "";
    rejectPendingRpcRequests("Socket closed before request completed.");
    if (state.connectionState === "encrypted") {
      setConnectionState("trusted_host");
    } else if (state.connectionState !== "not_paired") {
      setConnectionState("disconnected");
    }
    logEvent(`Socket closed (code=${closeCode}${closeReason ? `, reason=${closeReason}` : ""})`);
  });

  socket.addEventListener("error", () => {
    setError("WebSocket connection failed. Verify Tailscale is connected on both devices and relay URL is reachable.");
    logEvent("WebSocket error event.");
  });
}

async function handleWireMessage(text) {
  const parsed = safeParseJSON(text);
  if (!parsed || typeof parsed !== "object") {
    logEvent(`Wire: ${text}`);
    return;
  }

  if (parsed.kind === "secureError") {
    setError(`Secure error (${parsed.code}): ${parsed.message}`);
    if (parsed.code === "pairing_auth_failed" || parsed.code === "pairing_expired") {
      setConnectionState("re_pair_required");
    }
    return;
  }

  if (parsed.kind === "serverHello") {
    await handleServerHello(parsed);
    return;
  }

  if (parsed.kind === "secureReady") {
    handleSecureReady(parsed);
    return;
  }

  if (parsed.kind === "encryptedEnvelope") {
    await handleEncryptedEnvelope(parsed);
    return;
  }

  logEvent(`Wire: ${text}`);
}

async function handleServerHello(serverHello) {
  const pending = state.pendingHandshake;
  if (!pending) {
    return;
  }

  if (serverHello.protocolVersion !== PROTOCOL_VERSION) {
    setConnectionState("update_required");
    return setError("Protocol mismatch. Update bridge/web client.");
  }
  if (serverHello.sessionId !== pending.sessionId || serverHello.hostDeviceId !== pending.hostDeviceId) {
    setConnectionState("re_pair_required");
    return setError("Session/host mismatch during secure handshake.");
  }
  if (serverHello.hostIdentityPublicKey !== pending.hostIdentityPublicKey) {
    setConnectionState("re_pair_required");
    return setError("Host identity mismatch. Re-pair required.");
  }

  const transcript = buildHandshakeTranscript({
    sessionId: pending.sessionId,
    protocolVersion: serverHello.protocolVersion,
    handshakeMode: serverHello.handshakeMode,
    keyEpoch: serverHello.keyEpoch,
    hostDeviceId: serverHello.hostDeviceId,
    androidDeviceId: state.identity.androidDeviceId,
    hostIdentityPublicKey: serverHello.hostIdentityPublicKey,
    androidIdentityPublicKey: state.identity.androidIdentityPublicKey,
    hostEphemeralPublicKey: serverHello.hostEphemeralPublicKey,
    androidEphemeralPublicKey: bytesToBase64(pending.ephemeralPublicRaw),
    clientNonce: pending.clientNonce,
    serverNonce: base64ToBytes(serverHello.serverNonce),
    expiresAtForTranscript: serverHello.expiresAtForTranscript,
  });

  const hostKey = await importEd25519PublicKey(serverHello.hostIdentityPublicKey);
  const signatureValid = await crypto.subtle.verify(
    "Ed25519",
    hostKey,
    base64ToBytes(serverHello.hostSignature),
    transcript
  );
  if (!signatureValid) {
    setConnectionState("re_pair_required");
    return setError("Host signature validation failed.");
  }

  const hostEphemeralPublicKey = await crypto.subtle.importKey(
    "raw",
    base64ToBytes(serverHello.hostEphemeralPublicKey),
    { name: "X25519" },
    false,
    []
  );
  const sharedSecretBuffer = await crypto.subtle.deriveBits(
    { name: "X25519", public: hostEphemeralPublicKey },
    pending.ephemeralPrivateKey,
    256
  );
  const sharedSecret = new Uint8Array(sharedSecretBuffer);
  const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", transcript));
  const infoPrefix = `${HANDSHAKE_TAG}|${serverHello.sessionId}|${serverHello.hostDeviceId}|${state.identity.androidDeviceId}|${serverHello.keyEpoch}`;
  const androidToHostKey = await deriveAesKey(sharedSecret, salt, `${infoPrefix}|androidToHost`);
  const hostToAndroidKey = await deriveAesKey(sharedSecret, salt, `${infoPrefix}|hostToAndroid`);

  const identityPrivateKey = await importEd25519PrivateKey(state.identity.androidIdentityPrivateKey);
  const clientAuthTranscript = concatBytes(transcript, encodeUtf8LP("client-auth"));
  const clientSignatureBuffer = await crypto.subtle.sign("Ed25519", identityPrivateKey, clientAuthTranscript);

  state.secureSession = {
    sessionId: serverHello.sessionId,
    keyEpoch: serverHello.keyEpoch,
    hostDeviceId: serverHello.hostDeviceId,
    hostIdentityPublicKey: serverHello.hostIdentityPublicKey,
    androidToHostKey,
    hostToAndroidKey,
    lastInboundCounter: -1,
    nextOutboundCounter: 0,
  };

  state.ws?.send(JSON.stringify({
    kind: "clientAuth",
    sessionId: serverHello.sessionId,
    androidDeviceId: state.identity.androidDeviceId,
    keyEpoch: serverHello.keyEpoch,
    androidSignature: bytesToBase64(new Uint8Array(clientSignatureBuffer)),
  }));
  logEvent("Sent clientAuth");
}

function handleSecureReady(secureReady) {
  if (!state.secureSession) {
    return;
  }
  if (
    secureReady.sessionId !== state.secureSession.sessionId
    || secureReady.keyEpoch !== state.secureSession.keyEpoch
    || secureReady.hostDeviceId !== state.secureSession.hostDeviceId
  ) {
    return;
  }

  const lastAppliedHostOutboundSeq = Number(localStorage.getItem(STORAGE_KEYS.lastAppliedHostSeq) || "0");
  state.ws?.send(JSON.stringify({
    kind: "resumeState",
    sessionId: state.secureSession.sessionId,
    keyEpoch: state.secureSession.keyEpoch,
    lastAppliedHostOutboundSeq,
  }));

  if (state.pendingHandshake?.mode === "qr_bootstrap") {
    rememberTrustedHost({
      hostDeviceId: state.pendingHandshake.hostDeviceId,
      hostIdentityPublicKey: state.pendingHandshake.hostIdentityPublicKey,
      relayUrl: state.pendingHandshake.relay,
    });
  }

  state.pendingHandshake = null;
  setConnectionState("encrypted");
  clearError();
  logEvent("Secure channel ready.");
  void ensureCodexInitialized().catch((error) => {
    setError(`Initialize failed: ${error.message}`);
  });
}

async function handleEncryptedEnvelope(envelope) {
  if (!state.secureSession) {
    return;
  }
  if (
    envelope.sessionId !== state.secureSession.sessionId
    || envelope.keyEpoch !== state.secureSession.keyEpoch
    || envelope.sender !== "host"
  ) {
    return;
  }
  const counter = Number(envelope.counter);
  if (!Number.isInteger(counter) || counter <= state.secureSession.lastInboundCounter) {
    return;
  }

  try {
    const nonce = secureNonce("host", counter);
    const ciphertext = base64ToBytes(envelope.ciphertext);
    const tag = base64ToBytes(envelope.tag);
    const sealed = concatBytes(ciphertext, tag);

    const plaintextBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      state.secureSession.hostToAndroidKey,
      sealed
    );
    state.secureSession.lastInboundCounter = counter;
    const payload = safeParseJSON(bytesToText(new Uint8Array(plaintextBuffer)));
    if (!payload || typeof payload.payloadText !== "string") {
      return;
    }
    if (Number.isInteger(payload.hostOutboundSeq) && payload.hostOutboundSeq > 0) {
      const current = Number(localStorage.getItem(STORAGE_KEYS.lastAppliedHostSeq) || "0");
      if (payload.hostOutboundSeq > current) {
        localStorage.setItem(STORAGE_KEYS.lastAppliedHostSeq, String(payload.hostOutboundSeq));
      }
    }
    processApplicationMessage(payload.payloadText);
  } catch {
    setConnectionState("re_pair_required");
    setError("Failed to decrypt host payload.");
  }
}

function processApplicationMessage(payloadText) {
  logEvent(payloadText);
  const parsed = safeParseJSON(payloadText);
  if (!parsed || typeof parsed !== "object") {
    return;
  }

  const responseId = parsed.id == null ? "" : String(parsed.id);
  if (responseId && state.pendingRpc.has(responseId)) {
    const pending = state.pendingRpc.get(responseId);
    state.pendingRpc.delete(responseId);
    clearTimeout(pending.timeoutId);
    if (parsed.error && typeof parsed.error === "object") {
      const message = normalizeNonEmptyString(parsed.error.message) || "Remote request failed.";
      pending.reject(new Error(message));
      if (message.toLowerCase().includes("not initialized")) {
        state.codexInitialized = false;
      }
    } else {
      pending.resolve(parsed.result ?? parsed);
    }
    return;
  }

  if (parsed.error && typeof parsed.error === "object") {
    const message = normalizeNonEmptyString(parsed.error.message) || "Remote request failed.";
    setError(message);
    if (message.toLowerCase().includes("not initialized")) {
      state.codexInitialized = false;
      void ensureCodexInitialized().catch(() => {
        // surfaced via setError by caller
      });
    }
  }

  const threadId =
    parsed?.params?.threadId
    || parsed?.params?.thread_id
    || parsed?.params?.thread?.id
    || parsed?.result?.thread?.id
    || parsed?.result?.threadId
    || parsed?.result?.thread_id
    || "";
  if (threadId) {
    state.activeThreadId = threadId;
    if (!els.threadIdInput.value) {
      els.threadIdInput.value = threadId;
    }
  }

  const method = typeof parsed.method === "string" ? parsed.method : "";
  if (method.toLowerCase().includes("approval")) {
    pushApproval({
      id: parsed.id || crypto.randomUUID(),
      method,
      payloadText,
    });
  }
}

async function sendPrompt() {
  const prompt = (els.promptInput.value || "").trim();
  if (!prompt) {
    return setError("Prompt is empty.");
  }

  try {
    await ensureCodexInitialized();
    const typedThreadId = (els.threadIdInput.value || "").trim();
    const threadId = typedThreadId || await ensureThreadId();
    if (!typedThreadId) {
      els.threadIdInput.value = threadId;
    }
    await sendRpcRequest("turn/start", {
      threadId,
      input: [
        {
          type: "text",
          text: prompt,
        },
      ],
    });
  } catch (error) {
    setError(`Send failed: ${error.message}`);
  }
}

async function ensureThreadId() {
  if (state.activeThreadId) {
    return state.activeThreadId;
  }

  const created = await sendRpcRequest("thread/start", {});
  const threadId = extractThreadIdFromResult(created);
  if (!threadId) {
    throw new Error("Could not create thread ID.");
  }
  state.activeThreadId = threadId;
  logEvent(`Using thread: ${threadId}`);
  return threadId;
}

function sendRpc(method, params) {
  const payload = JSON.stringify({
    id: crypto.randomUUID(),
    method,
    params,
  });
  void sendSecurePayload(payload).catch((error) => {
    setError(`Send failed: ${error.message}`);
  });
}

async function sendSecurePayload(payloadText) {
  if (!state.secureSession || !state.ws || state.ws.readyState !== WebSocket.OPEN) {
    setError("Not connected.");
    throw new Error("Not connected.");
  }

  try {
    const counter = state.secureSession.nextOutboundCounter;
    const appPayload = textToBytes(JSON.stringify({
      hostOutboundSeq: null,
      payloadText,
    }));
    const nonce = secureNonce("android", counter);
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      state.secureSession.androidToHostKey,
      appPayload
    );
    const encrypted = new Uint8Array(encryptedBuffer);
    const ciphertext = encrypted.slice(0, encrypted.length - 16);
    const tag = encrypted.slice(encrypted.length - 16);

    state.ws.send(JSON.stringify({
      kind: "encryptedEnvelope",
      v: PROTOCOL_VERSION,
      sessionId: state.secureSession.sessionId,
      keyEpoch: state.secureSession.keyEpoch,
      sender: "android",
      counter,
      ciphertext: bytesToBase64(ciphertext),
      tag: bytesToBase64(tag),
    }));

    state.secureSession.nextOutboundCounter += 1;
  } catch (error) {
    setError(`Send failed: ${error.message}`);
    throw error;
  }
}

function sendRpcRequest(method, params, timeoutMs = 15000) {
  const id = crypto.randomUUID();
  const payload = JSON.stringify({
    id,
    method,
    params,
  });

  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      state.pendingRpc.delete(id);
      reject(new Error(`Request timed out for ${method}.`));
    }, timeoutMs);
    state.pendingRpc.set(id, { resolve, reject, timeoutId });

    sendSecurePayload(payload).catch((error) => {
      clearTimeout(timeoutId);
      state.pendingRpc.delete(id);
      reject(error);
    });
  });
}

async function sendRpcNotification(method, params) {
  const payload = JSON.stringify({
    method,
    params,
  });
  await sendSecurePayload(payload);
}

async function ensureCodexInitialized() {
  if (state.codexInitialized) {
    return;
  }
  if (state.initializingPromise) {
    return state.initializingPromise;
  }

  state.initializingPromise = (async () => {
    try {
      await sendRpcRequest("initialize", {
        clientInfo: {
          name: "androdex-web",
          title: "Androdex Web",
          version: "0.1.0",
        },
      });
    } catch (error) {
      const message = normalizeNonEmptyString(error?.message);
      if (!message.toLowerCase().includes("already initialized")) {
        throw error;
      }
    }

    await sendRpcNotification("initialized", {});
    state.codexInitialized = true;
    logEvent("Codex protocol initialized.");
  })();

  try {
    await state.initializingPromise;
  } finally {
    state.initializingPromise = null;
  }
}

function rejectPendingRpcRequests(reason) {
  for (const [id, pending] of state.pendingRpc.entries()) {
    clearTimeout(pending.timeoutId);
    pending.reject(new Error(reason));
    state.pendingRpc.delete(id);
  }
}

function disconnectSocket() {
  if (state.ws && state.ws.readyState <= WebSocket.OPEN) {
    state.ws.close();
  }
  state.ws = null;
  state.pendingHandshake = null;
  state.secureSession = null;
}

async function startQrScanner() {
  clearError();
  if (!isCameraSecureContext()) {
    const message = "Camera scan requires HTTPS (or localhost). Open the app over HTTPS, or paste pairing payload manually.";
    els.scannerHint.textContent = message;
    return setError(message);
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    const message = "Camera API is not available in this browser. Paste pairing payload manually.";
    els.scannerHint.textContent = message;
    return setError(message);
  }
  if (!("BarcodeDetector" in window)) {
    const message = "QR scanning is not supported in this browser (BarcodeDetector missing). Use paste fallback.";
    els.scannerHint.textContent = message;
    return setError(message);
  }
  try {
    stopQrScanner();
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
      audio: false,
    });
    state.scannerStream = stream;
    els.qrVideo.srcObject = stream;
    els.qrVideo.classList.remove("hidden");
    state.scannerDetector = new BarcodeDetector({ formats: ["qr_code"] });
    state.scannerTimer = setInterval(async () => {
      if (!state.scannerDetector || !els.qrVideo.srcObject) {
        return;
      }
      try {
        const results = await state.scannerDetector.detect(els.qrVideo);
        if (results?.length) {
          const rawValue = results[0].rawValue || "";
          if (rawValue) {
            els.pairingPayloadInput.value = rawValue;
            logEvent("QR payload scanned from camera.");
            stopQrScanner();
          }
        }
      } catch {
        // ignore scan frame errors
      }
    }, 450);
    els.scannerHint.textContent = "Camera scanning active.";
  } catch (error) {
    setError(`Camera scan failed: ${error.message}`);
  }
}

function stopQrScanner() {
  if (state.scannerTimer) {
    clearInterval(state.scannerTimer);
    state.scannerTimer = null;
  }
  if (state.scannerStream) {
    state.scannerStream.getTracks().forEach((track) => track.stop());
    state.scannerStream = null;
  }
  state.scannerDetector = null;
  els.qrVideo.srcObject = null;
  els.qrVideo.classList.add("hidden");
  els.scannerHint.textContent = "Camera scan stopped.";
}

function refreshScannerAvailabilityHint() {
  if (!isCameraSecureContext()) {
    els.scannerHint.textContent = "Camera scan needs HTTPS on phone browsers. Paste pairing payload fallback is available.";
    return;
  }
  if (!("BarcodeDetector" in window)) {
    els.scannerHint.textContent = "This browser cannot decode QR from camera. Paste pairing payload fallback is available.";
    return;
  }
  els.scannerHint.textContent = "Camera scan ready. If it fails, use paste fallback.";
}

function isCameraSecureContext() {
  if (window.isSecureContext) {
    return true;
  }
  const hostname = String(location.hostname || "").toLowerCase();
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function parsePairingPayload(rawPayload) {
  try {
    const parsed = JSON.parse(rawPayload);
    if (Number(parsed.v) !== PAIRING_QR_VERSION) {
      return { ok: false, error: `Unsupported pairing version: ${parsed.v}` };
    }
    if (!parsed.relay || !parsed.sessionId || !parsed.hostDeviceId || !parsed.hostIdentityPublicKey) {
      return { ok: false, error: "Pairing payload is incomplete." };
    }
    if (!Number(parsed.expiresAt) || Number(parsed.expiresAt) < Date.now()) {
      return { ok: false, error: "Pairing payload is expired." };
    }
    return {
      ok: true,
      value: {
        relay: String(parsed.relay).trim(),
        sessionId: String(parsed.sessionId).trim(),
        hostDeviceId: String(parsed.hostDeviceId).trim(),
        hostIdentityPublicKey: String(parsed.hostIdentityPublicKey).trim(),
      },
    };
  } catch {
    return { ok: false, error: "Invalid pairing JSON." };
  }
}

function ensureInitialized() {
  if (!state.bootstrapped || !state.identity) {
    throw new Error("Client is not initialized. Reload the page and try again.");
  }
}

function saveRelaySession(session) {
  state.relaySession = session;
  localStorage.setItem(STORAGE_KEYS.relaySession, JSON.stringify(session));
}

function loadRelaySession() {
  const raw = localStorage.getItem(STORAGE_KEYS.relaySession);
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed.relay || !parsed.sessionId || !parsed.hostDeviceId || !parsed.hostIdentityPublicKey) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function rememberTrustedHost({ hostDeviceId, hostIdentityPublicKey, relayUrl }) {
  const existing = state.trustedHosts[hostDeviceId] || {};
  state.trustedHosts[hostDeviceId] = {
    hostDeviceId,
    hostIdentityPublicKey,
    relayUrl,
    lastUsedAt: Date.now(),
    lastPairedAt: existing.lastPairedAt || Date.now(),
    displayName: existing.displayName || "",
  };
  localStorage.setItem(STORAGE_KEYS.trustedHosts, JSON.stringify(state.trustedHosts));
}

function loadTrustedHosts() {
  const raw = localStorage.getItem(STORAGE_KEYS.trustedHosts);
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function preferredTrustedHost() {
  const records = Object.values(state.trustedHosts);
  if (!records.length) {
    return null;
  }
  records.sort((a, b) => Number(b.lastUsedAt || 0) - Number(a.lastUsedAt || 0));
  return records[0];
}

async function loadOrCreateIdentity() {
  const existingRaw = localStorage.getItem(STORAGE_KEYS.identity);
  if (existingRaw) {
    try {
      const parsed = JSON.parse(existingRaw);
      if (parsed.androidDeviceId && parsed.androidIdentityPrivateKey && parsed.androidIdentityPublicKey) {
        return parsed;
      }
    } catch {
      // regenerate
    }
  }

  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const privateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const created = {
    androidDeviceId: crypto.randomUUID(),
    androidIdentityPrivateKey: bytesToBase64(privateKey),
    androidIdentityPublicKey: bytesToBase64(publicKey),
  };
  localStorage.setItem(STORAGE_KEYS.identity, JSON.stringify(created));
  return created;
}

async function ensureCryptoSupport() {
  if (!window.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this browser.");
  }
  const ed25519Supported = await supportsAlgorithm("Ed25519", ["sign", "verify"]);
  const x25519Supported = await supportsAlgorithm("X25519", ["deriveBits"]);

  if (!ed25519Supported || !x25519Supported) {
    const missing = [
      ed25519Supported ? null : "Ed25519",
      x25519Supported ? null : "X25519",
    ].filter(Boolean).join(", ");
    throw new Error(`Browser cryptography support is missing (${missing}). Use a newer Chrome/Edge browser.`);
  }
}

async function supportsAlgorithm(name, usages) {
  try {
    const generated = await crypto.subtle.generateKey({ name }, true, usages);
    if (!generated || !generated.privateKey || !generated.publicKey) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function trustedResolveEndpoint(relayUrl) {
  const normalized = String(relayUrl || "").replace(/\/+$/, "");
  const httpBase = normalized
    .replace(/^wss:\/\//i, "https://")
    .replace(/^ws:\/\//i, "http://");
  if (httpBase.endsWith("/relay")) {
    return `${httpBase.slice(0, -"/relay".length)}/v1/trusted/session/resolve`;
  }
  return `${httpBase}/v1/trusted/session/resolve`;
}

function relayWebSocketUrl(relayUrl, sessionId) {
  const normalized = String(relayUrl || "").replace(/\/+$/, "");
  const base = normalized.endsWith("/relay")
    ? `${normalized}/${sessionId}`
    : `${normalized}/relay/${sessionId}`;
  try {
    const url = new URL(base);
    if (!url.searchParams.get("role")) {
      url.searchParams.set("role", "android");
    }
    return url.toString();
  } catch {
    const separator = base.includes("?") ? "&" : "?";
    return `${base}${separator}role=android`;
  }
}

async function importEd25519PublicKey(base64) {
  return crypto.subtle.importKey(
    "spki",
    base64ToBytes(base64),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
}

async function importEd25519PrivateKey(base64) {
  return crypto.subtle.importKey(
    "pkcs8",
    base64ToBytes(base64),
    { name: "Ed25519" },
    false,
    ["sign"]
  );
}

async function deriveAesKey(sharedSecretBytes, saltBytes, infoLabel) {
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecretBytes, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: textToBytes(infoLabel),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function buildHandshakeTranscript({
  sessionId,
  protocolVersion,
  handshakeMode,
  keyEpoch,
  hostDeviceId,
  androidDeviceId,
  hostIdentityPublicKey,
  androidIdentityPublicKey,
  hostEphemeralPublicKey,
  androidEphemeralPublicKey,
  clientNonce,
  serverNonce,
  expiresAtForTranscript,
}) {
  return concatBytes(
    encodeUtf8LP(HANDSHAKE_TAG),
    encodeUtf8LP(sessionId),
    encodeUtf8LP(String(protocolVersion)),
    encodeUtf8LP(handshakeMode),
    encodeUtf8LP(String(keyEpoch)),
    encodeUtf8LP(hostDeviceId),
    encodeUtf8LP(androidDeviceId),
    encodeDataLP(base64ToBytes(hostIdentityPublicKey)),
    encodeDataLP(base64ToBytes(androidIdentityPublicKey)),
    encodeDataLP(base64ToBytes(hostEphemeralPublicKey)),
    encodeDataLP(base64ToBytes(androidEphemeralPublicKey)),
    encodeDataLP(clientNonce),
    encodeDataLP(serverNonce),
    encodeUtf8LP(String(expiresAtForTranscript))
  );
}

function secureNonce(sender, counter) {
  const nonce = new Uint8Array(12);
  nonce[0] = sender === "host" ? 1 : 2;
  let value = BigInt(counter);
  for (let index = 11; index >= 1; index -= 1) {
    nonce[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return nonce;
}

function pushApproval(entry) {
  state.approvals.unshift(entry);
  state.approvals = state.approvals.slice(0, 20);
  renderApprovals();
}

function renderApprovals() {
  if (!state.approvals.length) {
    els.approvalList.className = "list muted";
    els.approvalList.textContent = "No approval prompts yet.";
    return;
  }
  els.approvalList.className = "list";
  els.approvalList.textContent = "";
  for (const approval of state.approvals) {
    const wrapper = document.createElement("div");
    wrapper.className = "approval-item";
    const title = document.createElement("div");
    title.className = "approval-title";
    title.textContent = approval.method;
    const body = document.createElement("div");
    body.className = "approval-body";
    body.textContent = approval.payloadText;

    const actions = document.createElement("div");
    actions.className = "actions";

    const approveBtn = document.createElement("button");
    approveBtn.textContent = "Approve";
    approveBtn.addEventListener("click", () => {
      sendRpc("approval/approve", { requestId: approval.id });
    });

    const denyBtn = document.createElement("button");
    denyBtn.textContent = "Deny";
    denyBtn.addEventListener("click", () => {
      sendRpc("approval/deny", { requestId: approval.id });
    });

    actions.append(approveBtn, denyBtn);
    wrapper.append(title, body, actions);
    els.approvalList.appendChild(wrapper);
  }
}

function setConnectionState(value) {
  state.connectionState = value;
  const labels = {
    not_paired: "Not paired",
    trusted_host: "Trusted host",
    resolving_trusted: "Resolving trusted session",
    handshaking: "Secure handshake in progress",
    reconnecting: "Reconnecting securely",
    encrypted: "End-to-end encrypted",
    disconnected: "Disconnected",
    re_pair_required: "Re-pair required",
    update_required: "Update required",
  };
  els.statusText.textContent = labels[value] || value;
}

function setError(message) {
  state.lastError = message;
  els.errorText.textContent = message;
  els.errorText.classList.remove("hidden");
}

function clearError() {
  state.lastError = "";
  els.errorText.classList.add("hidden");
  els.errorText.textContent = "";
}

function logEvent(text) {
  const now = new Date().toLocaleTimeString();
  const line = `[${now}] ${text}`;
  els.eventLog.textContent = `${line}\n${els.eventLog.textContent}`.slice(0, 30_000);
}

function shortId(value) {
  return String(value || "").slice(0, 8);
}

function safeParseJSON(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function normalizeNonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function extractThreadIdFromResult(result) {
  if (!result || typeof result !== "object") {
    return "";
  }
  return normalizeNonEmptyString(
    result?.thread?.id
    || result?.threadId
    || result?.thread_id
    || result?.id
  );
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function encodeUtf8LP(value) {
  return encodeDataLP(textToBytes(String(value)));
}

function encodeDataLP(bytes) {
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, bytes.length, false);
  return concatBytes(prefix, bytes);
}

function concatBytes(...chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return merged;
}

function textToBytes(value) {
  return new TextEncoder().encode(value);
}

function bytesToText(value) {
  return new TextDecoder().decode(value);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
