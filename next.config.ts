import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  typescript: {
    ignoreBuildErrors: false,
  },
  reactStrictMode: true,
  output: "standalone",
  serverExternalPackages: ["better-sqlite3"],
};

export default nextConfig;
