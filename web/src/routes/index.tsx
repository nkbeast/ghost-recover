import { createFileRoute } from "@tanstack/react-router";
import { Nav } from "@/components/ghost/Nav";
import { Hero } from "@/components/ghost/Hero";
import { Stats } from "@/components/ghost/Stats";
import { Capabilities } from "@/components/ghost/Capabilities";
import { Screens } from "@/components/ghost/Screens";
import { Filesystems } from "@/components/ghost/Filesystems";
import { Carving } from "@/components/ghost/Carving";
import { HiddenGems } from "@/components/ghost/HiddenGems";
import { Architecture } from "@/components/ghost/Architecture";
import { Proof } from "@/components/ghost/Proof";
import { GetStarted } from "@/components/ghost/GetStarted";
import { FaqRoadmap } from "@/components/ghost/FaqRoadmap";
import { FinalCta } from "@/components/ghost/FinalCta";

const title = "GHOST RECOVER — Linux Data Recovery Engine (44 filesystems, 315 carvers)";
const description =
  "Open-source Linux data recovery: recover deleted files from 44 filesystems, carve 315 file formats, rebuild RAID arrays, clone failing drives. Read-only first, MIT licensed.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      {
        property: "og:image",
        content: "https://raw.githubusercontent.com/nkbeast/ghost-recover/main/assets/preview.png",
      },
      {
        name: "twitter:image",
        content: "https://raw.githubusercontent.com/nkbeast/ghost-recover/main/assets/preview.png",
      },
    ],
  }),
  component: Index,
});

function Index() {
  return (
    <div className="min-h-screen bg-background">
      <Nav />
      <main>
        <Hero />
        <Stats />
        <Capabilities />
        <Screens />
        <Filesystems />
        <Carving />
        <HiddenGems />
        <Architecture />
        <Proof />
        <GetStarted />
        <FaqRoadmap />
        <FinalCta />
      </main>
    </div>
  );
}
