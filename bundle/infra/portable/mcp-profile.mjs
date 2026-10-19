// The independent local fixture excludes provider OAuth configuration.
// Reject it rather than importing candidate product policy into the host.
export function mcpPolicy(profile) {
  if (profile.product?.mcpOAuth) throw new Error('INDEPENDENT_PROVIDER_OAUTH_PROFILE_UNSUPPORTED');
  return null;
}
export function mcpRoutes(enabled) {
  if (enabled) throw new Error('INDEPENDENT_PROVIDER_OAUTH_PROFILE_UNSUPPORTED');
  return '';
}
