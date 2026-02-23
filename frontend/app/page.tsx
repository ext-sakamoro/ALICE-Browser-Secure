import Link from "next/link";

const features = [
  {
    title: "Browser Isolation",
    description:
      "Execute untrusted URLs inside isolated sessions with configurable timeouts and viewport sizes. Zero local execution risk.",
    icon: "🔒",
  },
  {
    title: "Tracker Analysis",
    description:
      "Scan any URL and receive a breakdown of tracker count, ad count, and fingerprinting risk level before the page loads.",
    icon: "🔍",
  },
  {
    title: "Content Filtering",
    description:
      "Pass raw HTML through a rule engine that strips ads, trackers, and invasive scripts — returning clean, safe markup.",
    icon: "🧹",
  },
];

export default function HomePage() {
  return (
    <main className="min-h-screen bg-gray-950 text-white">
      {/* Hero */}
      <section className="flex flex-col items-center justify-center px-6 py-32 text-center">
        <p className="mb-3 text-sm font-semibold uppercase tracking-widest text-emerald-400">
          ALICE Browser Secure
        </p>
        <h1 className="mb-4 text-5xl font-extrabold leading-tight md:text-6xl">
          Don&apos;t browse blindly.
          <br />
          <span className="text-emerald-400">Browse the law of privacy.</span>
        </h1>
        <p className="mb-8 max-w-xl text-lg text-gray-400">
          Secure browser isolation powered by ALICE-Browser. Isolate sessions,
          detect trackers, and filter content — all before a single byte reaches
          the user.
        </p>
        <div className="flex gap-4">
          <Link
            href="/dashboard/console"
            className="rounded-lg bg-emerald-600 px-6 py-3 font-semibold text-white hover:bg-emerald-500 transition-colors"
          >
            Open Console
          </Link>
          <Link
            href="#features"
            className="rounded-lg border border-gray-700 px-6 py-3 font-semibold text-gray-300 hover:border-emerald-500 hover:text-white transition-colors"
          >
            Learn More
          </Link>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="px-6 pb-24">
        <div className="mx-auto max-w-5xl">
          <h2 className="mb-12 text-center text-3xl font-bold">
            What ALICE Browser Secure gives you
          </h2>
          <div className="grid gap-8 md:grid-cols-3">
            {features.map((f) => (
              <div
                key={f.title}
                className="rounded-xl border border-gray-800 bg-gray-900 p-6"
              >
                <div className="mb-3 text-3xl">{f.icon}</div>
                <h3 className="mb-2 text-xl font-semibold">{f.title}</h3>
                <p className="text-gray-400">{f.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-8 text-center text-sm text-gray-600">
        ALICE Browser Secure — AGPL-3.0
      </footer>
    </main>
  );
}
