  function saveBlob(blob, filename) {
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = filename;
    anchor.rel = "noopener";
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    // Give the browser a moment to start the download before releasing it.
    setTimeout(() => URL.revokeObjectURL(href), 30000);
  }

  async function downloadLauncher(btn) {
    if (!btn || btn.disabled) return;
    const url = String(btn.getAttribute("data-download") || "").trim();
    const filename = String(btn.getAttribute("data-filename") || "scriptsentry.py").trim();
    const hint = btn.parentElement ? btn.parentElement.querySelector(".download-hint") : null;
    const original = btn.textContent;
    if (!url) return;

    btn.disabled = true;
    btn.textContent = "⏳ Downloading…";
    if (hint) hint.textContent = "";

    try {
      const res = await fetch(url, { mode: "cors", cache: "no-store", credentials: "omit" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      if (!text.trim()) throw new Error("empty file");
      saveBlob(new Blob([text], { type: "text/x-python;charset=utf-8" }), filename);
      if (hint) hint.textContent = `✅ Downloaded ${filename}`;
      btn.textContent = "✅ Downloaded";
    } catch {
      // Last resort: open it so the user can still save it manually.
      if (hint) hint.textContent = "⚠️ Couldn't save automatically — opened in a new tab.";
      window.open(url, "_blank", "noopener,noreferrer");
    } finally {
      setTimeout(() => {
        btn.textContent = original;
        btn.disabled = false;
      }, 1800);
    }
  }

  /* ---------------- Scroll experience ---------------- */

  const REVEAL_SELECTOR = [
    ".section-head",
    ".feature-card",
    ".step-card",
    ".notice-card",
    ".trust-row",
    ".setup-card",
    ".connect-card",
    ".console",
    ".tool-hero",
    ".footer-brand",
    ".footer-col",
  ].join(", ");

  // Reveal blocks as they scroll into view (once, then stop observing).
  function initReveal() {
    const nodes = $$(REVEAL_SELECTOR);
    if (!nodes.length) return;

    if (!("IntersectionObserver" in window) ||
        window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      nodes.forEach((el) => el.classList.add("is-visible"));
      return;
    }

    nodes.forEach((el) => {
      // Stagger siblings so a grid of cards cascades instead of popping.
      const siblings = Array.from(el.parentElement ? el.parentElement.children : []);
      const index = Math.max(0, siblings.indexOf(el));
      el.style.setProperty("--reveal-delay", `${Math.min(index, 7) * 70}ms`);
    });

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 },
    );

    nodes.forEach((el) => {
      // Anything already on screen at load reveals immediately.
      const box = el.getBoundingClientRect();
      if (box.top < window.innerHeight * 0.9) el.classList.add("is-visible");
      else observer.observe(el);
    });
  }

  // Thin progress bar under the sticky header.
  /* The sticky header sits over the page content, so once the page scrolls it
   * needs a solid background and a shadow to stay legible against whatever
   * passes underneath. The translucent blur alone is not enough over bright
   * cards. A class toggle (not an inline style) keeps it in the stylesheet. */
  function initStickyHeader() {
    const header = $("#site-header");
    if (!header) return;
    let queued = false;
    const apply = () => {
      queued = false;
      header.classList.toggle("is-stuck", window.scrollY > 8);
    };
    window.addEventListener("scroll", () => {
      if (queued) return;
      queued = true;
      window.requestAnimationFrame(apply);
    }, { passive: true });
    apply();
  }

  // The footer "view the setup guide" link should open the dialog that
  // actually contains the guide, not just scroll near it.
  function initSetupLinks() {
    $$(".js-open-setup").forEach((link) => {
      link.addEventListener("click", (event) => {
        // Only hijack it on pages that have the dialog; otherwise let the
        // href do its normal cross-page navigation.
        if (!$("#privacy-modal")) return;
        event.preventDefault();
        openPrivacyModal();
      });
    });
  }

  function initScrollProgress() {
    const bar = $("#scroll-progress");
    if (!bar) return;
    let queued = false;
    const update = () => {
      queued = false;
      const doc = document.documentElement;
      const max = doc.scrollHeight - window.innerHeight;
      const ratio = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
      bar.style.transform = `scaleX(${ratio})`;
    };
    window.addEventListener("scroll", () => {
      if (queued) return;
      queued = true;
      window.requestAnimationFrame(update);
    }, { passive: true });
    window.addEventListener("resize", update, { passive: true });
    update();
  }

  // Highlight the nav link for whichever section is on screen.
  function initNavSpy() {
    const links = $$('.site-nav a[href^="#"]');
    if (!links.length || !("IntersectionObserver" in window)) return;
    const byId = new Map();
    links.forEach((link) => {
      const target = document.getElementById(link.getAttribute("href").slice(1));
      if (target) byId.set(target, link);
    });
    if (!byId.size) return;

    const current = $("#nav-current");
    const setActive = (link) => {
      links.forEach((l) => {
        const on = l === link;
        l.classList.toggle("is-active", on);
        if (on) l.setAttribute("aria-current", "true");
        else l.removeAttribute("aria-current");
      });
      // "You are here" label for narrow screens, where the nav is collapsed.
      if (current) current.textContent = link ? link.textContent.trim() : "Overview";
    };
    if (current) current.textContent = "Overview";

    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((e) => e.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (visible && byId.has(visible.target)) setActive(byId.get(visible.target));
    }, { rootMargin: "-25% 0px -60% 0px", threshold: [0.01, 0.25, 0.6] });

    byId.forEach((_, section) => observer.observe(section));
  }

  /* Shared page chrome: setup modal, engine pill, launcher downloads. */
  function initChrome() {
    $$(".js-download-launcher").forEach((btn) => {
      btn.addEventListener("click", () => downloadLauncher(btn));
    });

    const pill = $("#engine-status");
    if (pill) pill.addEventListener("click", openPrivacyModal);

    const heroSetup = $("#hero-setup");
    if (heroSetup) heroSetup.addEventListener("click", openPrivacyModal);

    // Demo report: renders a real engine report for a labelled example
    // bundle through the exact same pipeline a live scan uses. This is how
    // a first-time visitor on the hosted page sees the product before
    // installing anything -- and it can never advertise detections the
    // engine does not actually make, because the payload is generated by
    // the engine itself (tools/build_demo_payload.py).
    const demoBtn = $("#demo-report");
    if (demoBtn) demoBtn.addEventListener("click", () => {
      const show = () => {
        const demo = window.SS_DEMO_REPORT;
        if (!demo || !demo.summary) {
          showTransferNote("The demo report could not be loaded.", true);
          return;
        }
        payload = demo;
        renderDashboard();
        const results = $("#results");
        if (results) results.scrollIntoView({ behavior: "smooth", block: "start" });
      };
      if (window.SS_DEMO_REPORT) return show();
      const script = document.createElement("script");
      script.src = "../demo/report.js";
      script.onload = show;
      script.onerror = () => showTransferNote("The demo report could not be loaded.", true);
      document.head.appendChild(script);
    });

    const closeX = $("#close-modal-x");
    if (closeX) closeX.addEventListener("click", closePrivacyModal);

    // Clicking the dimmed backdrop also closes the dialog.
    const modal = $("#privacy-modal");
    if (modal) {
      modal.addEventListener("mousedown", (event) => {
        if (event.target === modal) closePrivacyModal();
      });
    }

    // Smooth in-page scrolling for the header / footer navigation.
    $$('a[href^="#"]').forEach((link) => {
      link.addEventListener("click", (event) => {
        const id = link.getAttribute("href").slice(1);
        if (!id) return;
        const target = document.getElementById(id);
        if (!target) return;
        event.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        if (history.replaceState) history.replaceState(null, "", `#${id}`);
      });
    });

    initReveal();
    initStickyHeader();
    initSetupLinks();
    initScrollProgress();
    initNavSpy();
    initMobileNav();
    initHelpTips();
  }

  /* ---------------- Help tooltips on touch ----------------
   * The tips are CSS-only on hover, which no phone has. Tap, click,
   * Enter and Space now toggle them, and a floating tip that would
   * hang off the edge of the viewport is nudged back into view.
   * (On touch/narrow screens CSS renders the tip inline instead, so
   * there is nothing to nudge and nothing that can clip.) */
  function initHelpTips() {
    const tips = $$(".help");
    if (!tips.length) return;

    // Matches the inline-expansion media query in styles.css.
    const inlineMode = window.matchMedia("(max-width: 700px), (pointer: coarse)");

    const closeAll = (except) => {
      tips.forEach((tip) => {
        if (tip !== except) {
          tip.classList.remove("is-open");
          tip.setAttribute("aria-expanded", "false");
        }
      });
    };

    // Keep a floating tip inside the viewport by shifting it sideways.
    const nudgeIntoView = (tip) => {
      if (inlineMode.matches) {
        tip.style.removeProperty("--tip-shift");
        return;
      }
      const width = parseFloat(getComputedStyle(tip, "::after").width) || 0;
      if (!width) return;
      const rect = tip.getBoundingClientRect();
      const center = rect.left + rect.width / 2;
      const margin = 10;
      const left = center - width / 2;
      const right = center + width / 2;
      let shift = 0;
      if (left < margin) shift = margin - left;
      else if (right > window.innerWidth - margin) shift = window.innerWidth - margin - right;
      tip.style.setProperty("--tip-shift", `${Math.round(shift)}px`);
    };

    tips.forEach((tip) => {
      // A disclosure, not a button-with-action, so the state is exposed.
      tip.setAttribute("role", "button");
      tip.setAttribute("aria-label", `What is this? ${tip.getAttribute("data-tip") || ""}`.trim());
      tip.setAttribute("aria-expanded", "false");

      const toggle = (event) => {
        if (event) event.preventDefault();
        const open = !tip.classList.contains("is-open");
        closeAll(tip);
        tip.classList.toggle("is-open", open);
        tip.setAttribute("aria-expanded", open ? "true" : "false");
        if (open) nudgeIntoView(tip);
      };

      tip.addEventListener("click", toggle);

      // Hover and keyboard focus show the tip through CSS alone; nudge it
      // back into the viewport at the same moment, or the first words of a
      // tip on a left-column field ("Profile ?") are clipped off-screen.
      tip.addEventListener("mouseenter", () => nudgeIntoView(tip));
      tip.addEventListener("focus", () => nudgeIntoView(tip));

      // A <span> does not fire click for Enter/Space the way a button
      // does, so keyboard activation is wired up explicitly.
      tip.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
          toggle(event);
        }
      });

      // Blur closes a focus-opened tip; a tapped one stays until dismissed.
      tip.addEventListener("blur", () => {
        tip.classList.remove("is-open");
        tip.setAttribute("aria-expanded", "false");
      });
    });

    document.addEventListener("click", (event) => {
      if (!event.target.closest(".help")) closeAll(null);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeAll(null);
    });

    // A tip measured at one width is wrong at another.
    window.addEventListener("resize", () => {
      tips.forEach((tip) => {
        tip.style.removeProperty("--tip-shift");
        tip.classList.remove("is-open");
        tip.setAttribute("aria-expanded", "false");
      });
    });
  }

  /* Below 1040px the section links collapse behind a menu button. Without
   * this a phone visitor could not reach any other part of the page. */
  function initMobileNav() {
    const header = $("#site-header");
    const toggle = $("#nav-toggle");
    const nav = $("#site-nav");
    if (!header || !toggle || !nav) return;

    const setOpen = (open) => {
      header.classList.toggle("nav-open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.setAttribute("aria-label", open ? "Close Navigation Menu" : "Open Navigation Menu");
    };

    toggle.addEventListener("click", () => setOpen(!header.classList.contains("nav-open")));

    // Tapping a section link should navigate and get the menu out of the way.
    nav.addEventListener("click", (event) => {
      if (event.target.closest("a")) setOpen(false);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && header.classList.contains("nav-open")) {
        setOpen(false);
        toggle.focus();
      }
    });

    document.addEventListener("click", (event) => {
      if (!header.contains(event.target)) setOpen(false);
    });

    // Leaving the collapsed layout with the menu open would strand it open.
    window.addEventListener("resize", () => {
      if (window.innerWidth > 1040) setOpen(false);
    });
  }
