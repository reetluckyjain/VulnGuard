import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  typescript: {
    ignoreBuildErrors: false,
  },
  reactStrictMode: true,
  serverExternalPackages: ["@neondatabase/serverless"],
};

export default nextConfig;
