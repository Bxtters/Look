/**
 * LOOK public config.
 * Set GOOGLE_CLIENT_ID to a Google Cloud "Web application" OAuth client ID
 * with authorized JavaScript origins including https://bxtters.github.io
 * (and http://localhost for local testing).
 *
 * You can also paste a client ID under Settings → Google Client ID on a device.
 */
export const GOOGLE_CLIENT_ID =
  (typeof localStorage !== "undefined" && localStorage.getItem("look.googleClientId")) ||
  "";
