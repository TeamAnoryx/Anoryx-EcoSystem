/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Never advertise the framework/version (small recon-reduction).
  poweredByHeader: false,
  // Self-contained server output for the node:20-slim runtime container (ADR-0015 D4).
  output: "standalone",
};

export default nextConfig;
