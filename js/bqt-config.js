/* ============================================================================
   BestQuoteTool — GO-LIVE CONFIGURATION
   ----------------------------------------------------------------------------
   This is the ONLY file that needs real values pasted in at launch.
   Everything else in the site reads from here.

   While a value below is EMPTY (""), the site keeps running in its current
   on-device mode for that piece — nothing breaks before launch:

     - SUPABASE_URL / SUPABASE_ANON_KEY empty
         -> Accounts stay on-device (today's signup gate), exactly as now.
     - STRIPE_LINK_BASE empty
         -> "Subscribe" buttons keep pointing at the landing subscribe block.
     - STRIPE_LINK_CLOUD empty
         -> The Cloud Saving add-on shows "checkout opens at launch".
     - LAUNCH_DATE empty
         -> The founding window is not open yet. It opens the day the
            real launch date is pasted in (see below).

   WHERE EACH VALUE COMES FROM (Franklin's launch steps):
     1. SUPABASE_URL + SUPABASE_ANON_KEY
        Supabase dashboard -> your project -> Settings -> API.
        The anon key is safe to publish: row-level security in schema.sql
        is what protects the data, not the key.
     2. STRIPE_LINK_BASE
        Stripe dashboard -> Payment Links: the $19/month BestQuoteTool
        subscription link.
     3. STRIPE_LINK_CLOUD
        Stripe dashboard -> Payment Links: the +$5/month Cloud Saving
        add-on link.
     4. LAUNCH_DATE
        Set this to the real go-live date ("YYYY-MM-DD") on launch day.
        The founding window is counted from it: subscriptions started in
        the first 30 days after this date lock the $19 base price
        (Terms Clause 6 — see founding_lock in schema.sql).

   After pasting values, also run schema.sql once in the Supabase SQL editor,
   and set the Supabase "Magic Link" email template to include {{ .Token }}
   so sign-in emails carry the 6-digit code the site asks for.
   ============================================================================ */
window.BQT_CONFIG = {
  /* ← PASTE: e.g. "https://abcdefghijklmnopqrst.supabase.co" */
  SUPABASE_URL: "",

  /* ← PASTE: the long "anon public" key from Settings -> API */
  SUPABASE_ANON_KEY: "",

  /* ← PASTE: Stripe Payment Link for BestQuoteTool — $19.00/month */
  STRIPE_LINK_BASE: "",

  /* ← PASTE: Stripe Payment Link for the Cloud Saving add-on — $5.00/month */
  STRIPE_LINK_CLOUD: "",

  /* ← SET AT LAUNCH: the real go-live date, "YYYY-MM-DD".
     Founding window = this date + 30 days (see note 4 above). */
  LAUNCH_DATE: ""
};
