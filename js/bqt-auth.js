/* ============================================================================
   BestQuoteTool — accounts, subscription status & Cloud Saving (Supabase)
   ----------------------------------------------------------------------------
   Reads its settings from js/bqt-config.js (window.BQT_CONFIG).

   FALLBACK CONTRACT: if the Supabase values in bqt-config.js are empty, or
   the Supabase library cannot load (offline, CDN blocked), this module
   reports configured = false and the pages keep using today's on-device
   gate, byte for byte. Nothing in here ever blocks the estimators.

   PRIVACY CONTRACT:
   - The client only READS the account's own profile flags (subscribed,
     cloud_saving, founding_lock + its price/start columns). Those flags
     are writable only by the service role (Stripe webhook) — see
     schema.sql column grants. Founding stamps happen in that same
     webhook at first activation; the client can know, never grant.
   - The client writes only: its own tests_used counter, its own
     cloud_enabled on/off preference, and its own documents rows.
   - Documents are uploaded ONLY when the signed-in subscriber has Cloud
     Saving entitled AND switched on. Otherwise nothing leaves the device.
   - Document deletes are SOFT deletes (deleted_at) so the Trash can
     restore them; delete-forever is the only hard delete.
   - OFFICE ACCESS: the client writes only the SHA-256 HASH of the
     account's office code (never the code), its own office_sessions rows,
     and one-time pairing token hashes. Code/pairing verification goes
     through the security-definer functions in schema.sql.
   ============================================================================ */
(function () {
  "use strict";
  var cfg = window.BQT_CONFIG || {};
  var sbUrl = String(cfg.SUPABASE_URL || "").trim();
  var sbKey = String(cfg.SUPABASE_ANON_KEY || "").trim();
  var configured = !!(sbUrl && sbKey && /^https:\/\//.test(sbUrl));

  var client = null;
  var currentUser = null;    // {id, email} once known
  var currentProfile = null; // row from public.profiles once loaded

  function g(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function s(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function rm(k) { try { localStorage.removeItem(k); } catch (e) {} }
  function emit() {
    try { window.dispatchEvent(new Event("bqt-auth-changed")); } catch (e) {}
  }

  /* Supabase persists its session in localStorage; peeking at it lets repeat
     visits know the account synchronously (the gate stays instant), while
     the real session check below verifies it in the background. */
  function peekUser() {
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (k && k.indexOf("sb-") === 0 && /-auth-token$/.test(k)) {
          var d = JSON.parse(localStorage.getItem(k) || "null");
          var u = d && (d.user || (d.currentSession && d.currentSession.user));
          if (u && u.id) return { id: u.id, email: u.email || null };
        }
      }
    } catch (e) {}
    return null;
  }
  if (configured) { var pk = peekUser(); if (pk) currentUser = pk; }

  function counterKey() { return currentUser ? ("bqt_tests_used::" + currentUser.id) : "bqt_tests_used"; }

  function syncMirrors() {
    if (!currentProfile) return;
    if (currentProfile.subscribed) s("bqt_profile_subscribed", "1"); else rm("bqt_profile_subscribed");
    if (currentProfile.cloud_saving) s("bqt_profile_cloud", "1"); else rm("bqt_profile_cloud");
    s("bqt_cloud_enabled", currentProfile.cloud_enabled === false ? "0" : "1");
    if (typeof currentProfile.tests_used === "number") s(counterKey(), String(currentProfile.tests_used));
  }
  function clearMirrors() {
    rm("bqt_profile_subscribed"); rm("bqt_profile_cloud");
  }

  function fetchProfile() {
    return client.from("profiles")
      .select("id,email,subscribed,cloud_saving,cloud_enabled,tests_used,founding_lock,locked_base_price_cents,subscription_started_at")
      .eq("id", currentUser.id).single()
      .then(function (res) {
        if (res.error) throw res.error;
        currentProfile = res.data; syncMirrors(); return currentProfile;
      });
  }
  function loadProfile() {
    if (!client || !currentUser) return Promise.resolve(null);
    return fetchProfile().catch(function () {
      /* Row normally created by the on_auth_user_created trigger; if it is
         missing (trigger not installed yet), create our own row — RLS and
         column grants keep the paid flags at their defaults. */
      return client.from("profiles")
        .insert({ id: currentUser.id, email: currentUser.email })
        .then(function () { return fetchProfile(); })
        .catch(function () { return null; });
    });
  }

  function loadScript(src, timeoutMs) {
    return new Promise(function (resolve, reject) {
      var sc = document.createElement("script"), done = false;
      var t = setTimeout(function () { if (!done) { done = true; reject(new Error("timeout")); } }, timeoutMs || 9000);
      sc.src = src;
      sc.onload = function () { if (!done) { done = true; clearTimeout(t); resolve(); } };
      sc.onerror = function () { if (!done) { done = true; clearTimeout(t); reject(new Error("load error")); } };
      document.head.appendChild(sc);
    });
  }

  var readyResolve;
  var ready = new Promise(function (res) { readyResolve = res; });
  function finishInit() { readyResolve(); emit(); }

  function init() {
    if (!configured) { finishInit(); return; }
    loadScript("https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js", 9000)
      .then(function () {
        if (!window.supabase || !window.supabase.createClient) throw new Error("supabase js missing");
        client = window.supabase.createClient(sbUrl, sbKey);
        return client.auth.getSession();
      })
      .then(function (res) {
        var session = res && res.data ? res.data.session : null;
        if (session && session.user) currentUser = { id: session.user.id, email: session.user.email || null };
        client.auth.onAuthStateChange(function (evt, sess) {
          currentUser = sess && sess.user ? { id: sess.user.id, email: sess.user.email || null } : null;
          if (currentUser) { loadProfile().then(emit); }
          else { currentProfile = null; clearMirrors(); emit(); }
        });
        if (currentUser) return loadProfile();
        return null;
      })
      .then(finishInit)
      .catch(function () {
        /* Configured but unreachable: degrade to the on-device gate. */
        client = null; currentProfile = null; clearMirrors();
        api.configured = false;
        finishInit();
      });
  }

  function signIn(email) {
    if (!client) return Promise.reject(new Error("Accounts are not available right now — please try again in a moment."));
    return client.auth.signInWithOtp({ email: email, options: { shouldCreateUser: true } })
      .then(function (res) { if (res.error) throw res.error; return true; });
  }
  function verify(email, token) {
    if (!client) return Promise.reject(new Error("Accounts are not available right now — please try again in a moment."));
    return client.auth.verifyOtp({ email: email, token: String(token || "").trim(), type: "email" })
      .then(function (res) {
        if (res.error) throw res.error;
        if (res.data && res.data.user) currentUser = { id: res.data.user.id, email: res.data.user.email || email };
        return loadProfile();
      })
      .then(function () { emit(); return currentUser; });
  }
  function signOut() {
    clearMirrors(); currentProfile = null;
    if (!client) { currentUser = null; emit(); return Promise.resolve(); }
    return client.auth.signOut().then(function () { currentUser = null; emit(); });
  }

  function testsUsed() {
    var n = parseInt(g(counterKey()) || "0", 10);
    return isNaN(n) ? 0 : n;
  }
  function setTestsUsed(n) {
    s(counterKey(), String(n));
    if (client && currentUser) {
      client.from("profiles").update({ tests_used: n }).eq("id", currentUser.id)
        .then(function () {}, function () {});
    }
  }

  function cloudEntitled() { return !!(currentProfile && currentProfile.cloud_saving); }
  function cloudEnabledPref() {
    if (currentProfile) return currentProfile.cloud_enabled !== false;
    return g("bqt_cloud_enabled") !== "0";
  }
  function cloudActive() {
    return !!(currentUser && currentProfile && currentProfile.subscribed &&
              currentProfile.cloud_saving && cloudEnabledPref());
  }
  function setCloudEnabled(b) {
    s("bqt_cloud_enabled", b ? "1" : "0");
    if (currentProfile) currentProfile.cloud_enabled = b;
    emit();
    if (client && currentUser) {
      return client.from("profiles").update({ cloud_enabled: b }).eq("id", currentUser.id)
        .then(function (res) { if (res.error) throw res.error; return true; });
    }
    return Promise.resolve(true);
  }

  function hashStr(str) {
    var h = 0;
    for (var i = 0; i < str.length; i++) { h = ((h << 5) - h + str.charCodeAt(i)) | 0; }
    return "h" + (h >>> 0);
  }
  var KIND_LABEL = { quote: "Quote", invoice: "Invoice", receipt: "Receipt", estimate: "Estimate" };

  /* Called by the gate after a document is generated. Uploads a snapshot of
     the tool's saved state ONLY for Cloud Saving subscribers with the
     switch on; a no-op for everyone else (nothing leaves their device). */
  function maybeSaveSnapshot(tool, kind, storeKey) {
    if (!cloudActive() || !client || !currentUser) return Promise.resolve(false);
    var raw = null;
    try { raw = localStorage.getItem(storeKey); } catch (e) {}
    if (!raw) return Promise.resolve(false);
    var doc;
    try { doc = JSON.parse(raw); } catch (e) { return Promise.resolve(false); }
    var h = hashStr(raw + "|" + kind), skey = "bqt_snap_" + tool + "_" + kind, last = null;
    try { last = sessionStorage.getItem(skey); } catch (e) {}
    if (last === h) return Promise.resolve(false);
    var title = (tool === "carpentry" ? "Carpentry" : "Painting") + " " +
      (KIND_LABEL[kind] || "Document") + " — " +
      new Date().toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
    return client.from("documents")
      .insert({ user_id: currentUser.id, tool: tool, kind: kind, title: title, doc: doc })
      .then(function (res) {
        if (res.error) throw res.error;
        try { sessionStorage.setItem(skey, h); } catch (e) {}
        return true;
      })
      .catch(function () { return false; });
  }
  function listDocuments(tool) {
    if (!client || !currentUser) return Promise.resolve([]);
    return client.from("documents")
      .select("id,tool,kind,title,created_at,updated_at,version")
      .eq("user_id", currentUser.id).eq("tool", tool)
      .is("deleted_at", null)
      .order("created_at", { ascending: false }).limit(50)
      .then(function (res) { if (res.error) throw res.error; return res.data || []; });
  }
  function listTrashedDocuments(tool) {
    if (!client || !currentUser) return Promise.resolve([]);
    return client.from("documents")
      .select("id,tool,kind,title,created_at,updated_at,version,deleted_at")
      .eq("user_id", currentUser.id).eq("tool", tool)
      .not("deleted_at", "is", null)
      .order("deleted_at", { ascending: false }).limit(50)
      .then(function (res) { if (res.error) throw res.error; return res.data || []; });
  }
  function fetchDocument(id) {
    if (!client || !currentUser) return Promise.reject(new Error("not signed in"));
    return client.from("documents")
      .select("id,tool,doc").eq("id", id).eq("user_id", currentUser.id).single()
      .then(function (res) { if (res.error) throw res.error; return res.data; });
  }
  /* Soft delete: the row stays, stamped with deleted_at, so the Trash view
     can restore it. Delete-forever (hardDeleteDocument) is the only erase. */
  function deleteDocument(id) {
    if (!client || !currentUser) return Promise.reject(new Error("not signed in"));
    return client.from("documents")
      .update({ deleted_at: new Date().toISOString() })
      .eq("id", id).eq("user_id", currentUser.id)
      .then(function (res) { if (res.error) throw res.error; return true; });
  }
  function restoreDocument(id) {
    if (!client || !currentUser) return Promise.reject(new Error("not signed in"));
    return client.from("documents")
      .update({ deleted_at: null })
      .eq("id", id).eq("user_id", currentUser.id)
      .then(function (res) { if (res.error) throw res.error; return true; });
  }
  function hardDeleteDocument(id) {
    if (!client || !currentUser) return Promise.reject(new Error("not signed in"));
    return client.from("documents").delete().eq("id", id).eq("user_id", currentUser.id)
      .then(function (res) { if (res.error) throw res.error; return true; });
  }

  /* ---------- Office Access (locked spec §2) --------------------------------
     The office code itself is generated in the gate (the account holder's
     browser) and NEVER sent or stored here — only its SHA-256 hash. These
     functions are inert when Supabase is not configured: the gate then runs
     the identical flow against on-device storage, exactly like the account
     fallback. Verification of a code typed on a device with no account
     session goes through the security-definer RPCs in schema.sql. */
  function getOfficeCode() {
    if (!client || !currentUser) return Promise.resolve(null);
    return client.from("office_codes")
      .select("code_hash,created_at,updated_at")
      .eq("user_id", currentUser.id).single()
      .then(function (res) {
        if (res.error) { if (res.error.code === "PGRST116") return null; throw res.error; }
        return res.data;
      })
      .catch(function () { return null; });
  }
  function setOfficeCodeHash(codeHash) {
    if (!client || !currentUser) return Promise.reject(new Error("not signed in"));
    return client.from("office_codes")
      .upsert({ user_id: currentUser.id, code_hash: codeHash }, { onConflict: "user_id" })
      .then(function (res) { if (res.error) throw res.error; return true; });
  }
  function listOfficeSessions() {
    if (!client || !currentUser) return Promise.resolve([]);
    return client.from("office_sessions")
      .select("id,label,created_at,last_seen_at,revoked_at")
      .eq("user_id", currentUser.id)
      .order("created_at", { ascending: false }).limit(50)
      .then(function (res) { if (res.error) throw res.error; return res.data || []; });
  }
  function addOfficeSession(label) {
    if (!client || !currentUser) return Promise.reject(new Error("not signed in"));
    return client.from("office_sessions")
      .insert({ user_id: currentUser.id, label: label || "Office session" })
      .select("id").single()
      .then(function (res) { if (res.error) throw res.error; return res.data; });
  }
  function revokeOfficeSession(id) {
    if (!client || !currentUser) return Promise.reject(new Error("not signed in"));
    return client.from("office_sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", id).eq("user_id", currentUser.id)
      .then(function (res) { if (res.error) throw res.error; return true; });
  }
  function createPairing(tokenHash, expiresAtIso) {
    if (!client || !currentUser) return Promise.reject(new Error("not signed in"));
    return client.from("office_pairings")
      .insert({ user_id: currentUser.id, token_hash: tokenHash, expires_at: expiresAtIso })
      .then(function (res) { if (res.error) throw res.error; return true; });
  }
  /* Verification calls — usable with NO account session (a helper's phone).
     They need only the Supabase client, not a signed-in user. */
  function redeemPairing(token, label) {
    if (!client) return Promise.reject(new Error("not configured"));
    return client.rpc("redeem_office_pairing", { p_token: token, p_label: label || null })
      .then(function (res) {
        if (res.error) throw res.error;
        var row = res.data && res.data[0];
        return row ? { email: row.account_email, sessionId: row.session_id } : null;
      });
  }
  function officeSigninLookup(codeHash, label) {
    if (!client) return Promise.reject(new Error("not configured"));
    return client.rpc("office_signin_lookup", { p_code_hash: codeHash, p_label: label || null })
      .then(function (res) {
        if (res.error) throw res.error;
        var row = res.data && res.data[0];
        return row ? { email: row.account_email, sessionId: row.session_id } : null;
      });
  }

  var api = {
    configured: configured,
    ready: ready,
    user: function () { return currentUser; },
    profile: function () { return currentProfile; },
    /* Founding price lock (read-only): true when this account subscribed
       inside the founding window and its $19 base price is locked.
       Stamped service-role side at activation — see schema.sql. */
    foundingLock: function () { return !!(currentProfile && currentProfile.founding_lock); },
    lockedBasePriceCents: function () {
      return currentProfile && typeof currentProfile.locked_base_price_cents === "number"
        ? currentProfile.locked_base_price_cents : null;
    },
    signIn: signIn,
    verify: verify,
    signOut: signOut,
    testsUsed: testsUsed,
    setTestsUsed: setTestsUsed,
    cloudEntitled: cloudEntitled,
    cloudEnabledPref: cloudEnabledPref,
    cloudActive: cloudActive,
    setCloudEnabled: setCloudEnabled,
    maybeSaveSnapshot: maybeSaveSnapshot,
    listDocuments: listDocuments,
    listTrashedDocuments: listTrashedDocuments,
    fetchDocument: fetchDocument,
    deleteDocument: deleteDocument,
    restoreDocument: restoreDocument,
    hardDeleteDocument: hardDeleteDocument,
    getOfficeCode: getOfficeCode,
    setOfficeCodeHash: setOfficeCodeHash,
    listOfficeSessions: listOfficeSessions,
    addOfficeSession: addOfficeSession,
    revokeOfficeSession: revokeOfficeSession,
    createPairing: createPairing,
    redeemPairing: redeemPairing,
    officeSigninLookup: officeSigninLookup,
    stripeLink: function (which) {
      var v = which === "cloud" ? cfg.STRIPE_LINK_CLOUD : cfg.STRIPE_LINK_BASE;
      return String(v || "").trim();
    }
  };
  window.BQTCloud = api;
  init();
})();
