import { useEffect, useState } from "react";
import { Github, Star, Menu, X } from "lucide-react";
import logo from "@/assets/ghost-recover-logo.png";
import { REPO_URL } from "@/lib/ghost-data";

const links = [
  { href: "#capabilities", label: "Capabilities" },
  { href: "#interface", label: "Interface" },
  { href: "#filesystems", label: "Filesystems" },
  { href: "#carving", label: "Carving" },
  { href: "#proof", label: "Proof" },
  { href: "#start", label: "Get started" },
];

export function Nav() {
  const [solid, setSolid] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setSolid(window.scrollY > 40);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-all duration-500 ${
        solid ? "border-b border-border/70 bg-background/80 backdrop-blur-xl" : "border-b border-transparent"
      }`}
    >
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-5 py-3.5">
        <a href="#top" className="group flex items-center gap-2.5">
          <img
            src={logo}
            alt="GHOST RECOVER logo"
            className="screen-logo h-9 w-9 transition-transform duration-500 group-hover:-translate-y-0.5"
          />
          <span className="font-mono text-sm font-bold tracking-[0.22em]">GHOST RECOVER</span>
          <span className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-widest text-primary">
            v1.0.0
          </span>
        </a>

        <div className="hidden items-center gap-7 lg:flex">
          {links.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="relative font-mono text-xs tracking-widest text-muted-foreground uppercase transition-colors hover:text-primary"
            >
              {l.label}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <a
            href={`${REPO_URL}/stargazers`}
            target="_blank"
            rel="noreferrer"
            className="hidden items-center gap-2 rounded-md border border-border bg-surface/60 px-3 py-2 font-mono text-xs text-muted-foreground transition-colors hover:border-primary/60 hover:text-primary sm:flex"
          >
            <Star className="h-3.5 w-3.5" />
            Star
          </a>
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
            className="glow-ring flex items-center gap-2 rounded-md bg-primary px-3.5 py-2 font-mono text-xs font-bold text-primary-foreground transition-transform hover:-translate-y-0.5"
          >
            <Github className="h-4 w-4" />
            GitHub
          </a>
          <button
            aria-label="Toggle menu"
            onClick={() => setOpen((v) => !v)}
            className="ml-1 rounded-md border border-border p-2 text-muted-foreground lg:hidden"
          >
            {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </nav>

      {open ? (
        <div className="border-t border-border bg-background/95 px-5 py-4 lg:hidden">
          <div className="grid gap-3">
            {links.map((l) => (
              <a
                key={l.href}
                href={l.href}
                onClick={() => setOpen(false)}
                className="font-mono text-xs tracking-widest text-muted-foreground uppercase"
              >
                {l.label}
              </a>
            ))}
          </div>
        </div>
      ) : null}
    </header>
  );
}
