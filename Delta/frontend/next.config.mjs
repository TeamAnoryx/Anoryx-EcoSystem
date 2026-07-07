/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Never advertise the framework/version (small recon-reduction).
  poweredByHeader: false,
  // Self-contained server output for a node:20-slim runtime container.
  output: "standalone",
};

export default nextConfig;
