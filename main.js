/**
 * ============================================================================
 * Mr Ifeanyi Portfolio - Core Architecture & Defense-in-Depth Security Engine
 * ============================================================================
 * Implements strict runtime client-side security controls:
 * 1. Anti-Clickjacking / Frame-Busting Guard
 * 2. Strict Input Sanitization & Normalization (Anti-XSS / Injection)
 * 3. Token-Bucket / Sliding-Window Client Rate Limiting
 * 4. Human-Interaction Time-Gate Challenge (Anti-Automation / Anti-Bot)
 * 5. Honeypot Trap Detection
 * 6. Form Action & Protocol Integrity Verification
 * 7. Reverse Tabnabbing Link Hardening
 * 8. Safe DOM Manipulation (Immune to DOM-based XSS)
 */

"use strict";

(function () {
    // -------------------------------------------------------------------------
    // 1. RUNTIME ANTI-CLICKJACKING & UI REDRESSING DEFENSE
    // -------------------------------------------------------------------------
    // Defense against being embedded in malicious iframe / framing attacks
    if (window.top !== window.self) {
        try {
            window.top.location = window.self.location;
        } catch (e) {
            // Cross-origin framing detected: neutralize parent framing
            window.location.replace("about:blank");
        }
    }

    // -------------------------------------------------------------------------
    // 2. CONFIGURATION & STATE (FROZEN TO PREVENT PROTOTYPE TAMPERING)
    // -------------------------------------------------------------------------
    const SECURITY_CONFIG = Object.freeze({
        MIN_SUBMISSION_TIME_MS: 3000,      // Minimum 3s to complete form (humans take 5-30s)
        RATE_LIMIT_MAX_REQUESTS: 3,        // Max 3 submissions per window
        RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 minute window
        COOLDOWN_PERIOD_MS: 20 * 1000,     // 20s minimum cooldown between submissions
        STORAGE_KEY: "__sec_rl_token",
        ALLOWED_FORM_ACTION_PREFIX: "https://formspree.io/f/",
        FIELD_LIMITS: Object.freeze({
            NAME_MAX: 100,
            NAME_MIN: 2,
            EMAIL_MAX: 254,
            SUBJECT_MAX: 150,
            MESSAGE_MAX: 3000,
            MESSAGE_MIN: 10
        })
    });

    // Capture precise page load timestamp for time-gate bot challenge
    const PAGE_INIT_TIMESTAMP = Date.now();

    // -------------------------------------------------------------------------
    // 3. SANITIZATION & VALIDATION ENGINE
    // -------------------------------------------------------------------------
    /**
     * Sanitizes raw text: strips control characters, normalizes Unicode, trims.
     * Prevents null byte injection, control-char evasion, and script containment breakouts.
     */
    function sanitizeText(input, maxLength) {
        if (typeof input !== "string") return "";
        // Normalize Unicode to NFC
        let sanitized = input.normalize("NFC");
        // Remove ASCII control characters (0x00-0x1F, 0x7F) except normal whitespace/newlines
        sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
        // Truncate to maximum allowed length
        if (maxLength && sanitized.length > maxLength) {
            sanitized = sanitized.substring(0, maxLength);
        }
        return sanitized.trim();
    }

    /**
     * Validates email against RFC 5322 compliant pattern
     */
    function isValidEmail(email) {
        if (!email || email.length > SECURITY_CONFIG.FIELD_LIMITS.EMAIL_MAX) return false;
        // Standard secure RFC 5322 regex
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
        return emailRegex.test(email);
    }

    /**
     * Validates name against safe character constraints (no dangerous brackets/scripts)
     */
    function isValidName(name) {
        if (!name || name.length < SECURITY_CONFIG.FIELD_LIMITS.NAME_MIN || name.length > SECURITY_CONFIG.FIELD_LIMITS.NAME_MAX) {
            return false;
        }
        // Disallow dangerous script tags, angle brackets, curly braces
        return !/[<>{}[\]\\/]/.test(name);
    }

    // -------------------------------------------------------------------------
    // 4. CLIENT-SIDE TOKEN BUCKET RATE LIMITER
    // -------------------------------------------------------------------------
    function checkRateLimit() {
        const now = Date.now();
        let history = [];
        try {
            const raw = sessionStorage.getItem(SECURITY_CONFIG.STORAGE_KEY);
            if (raw) {
                history = JSON.parse(raw);
                if (!Array.isArray(history)) history = [];
            }
        } catch (e) {
            history = [];
        }

        // Filter out records older than our rate-limit window
        history = history.filter(ts => typeof ts === "number" && (now - ts) < SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS);

        // Check 1: Cooldown between successive submissions
        if (history.length > 0) {
            const lastSubmission = history[history.length - 1];
            if (now - lastSubmission < SECURITY_CONFIG.COOLDOWN_PERIOD_MS) {
                const remainingSecs = Math.ceil((SECURITY_CONFIG.COOLDOWN_PERIOD_MS - (now - lastSubmission)) / 1000);
                return {
                    allowed: false,
                    reason: `Please wait ${remainingSecs} second${remainingSecs > 1 ? "s" : ""} before submitting again.`
                };
            }
        }

        // Check 2: Max submissions per window
        if (history.length >= SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS) {
            return {
                allowed: false,
                reason: "Submission limit reached for this session. Please email directly or try again later."
            };
        }

        return { allowed: true, history };
    }

    function recordSubmission(history) {
        try {
            history.push(Date.now());
            sessionStorage.setItem(SECURITY_CONFIG.STORAGE_KEY, JSON.stringify(history));
        } catch (e) {
            // SessionStorage quota or disabled; fails gracefully
        }
    }

    // -------------------------------------------------------------------------
    // 5. DOM INITIALIZATION & EVENT BINDINGS
    // -------------------------------------------------------------------------
    document.addEventListener("DOMContentLoaded", () => {
        // Set dynamic copyright year securely
        const copyrightEl = document.getElementById("copyright-year");
        if (copyrightEl) {
            copyrightEl.textContent = String(new Date().getFullYear());
        }

        // Secure Profile Image Error Fallback (replaces inline onerror handler)
        const profileImg = document.querySelector(".anchor-image");
        if (profileImg) {
            profileImg.addEventListener("error", function () {
                this.style.display = "none";
            });
        }

        // Hardening External Links Against Reverse Tabnabbing (rel="noopener noreferrer")
        const allLinks = document.querySelectorAll("a[href]");
        allLinks.forEach(link => {
            const href = link.getAttribute("href");
            if (href && (href.startsWith("http://") || href.startsWith("https://"))) {
                link.setAttribute("rel", "noopener noreferrer");
            }
        });

        // ---------------------------------------------------------------------
        // 6. RESPONSIVE MOBILE NAVIGATION
        // ---------------------------------------------------------------------
        const menuToggle = document.getElementById("menu-toggle");
        const navMenu = document.getElementById("nav-menu");
        const navItems = document.querySelectorAll(".nav-item");

        if (menuToggle && navMenu) {
            menuToggle.addEventListener("click", () => {
                const isExpanded = menuToggle.getAttribute("aria-expanded") === "true";
                menuToggle.setAttribute("aria-expanded", String(!isExpanded));
                menuToggle.classList.toggle("active");
                navMenu.classList.toggle("active");
            });

            navItems.forEach(item => {
                item.addEventListener("click", () => {
                    menuToggle.setAttribute("aria-expanded", "false");
                    menuToggle.classList.remove("active");
                    navMenu.classList.remove("active");
                });
            });

            document.addEventListener("click", (e) => {
                if (navMenu.classList.contains("active") && !navMenu.contains(e.target) && !menuToggle.contains(e.target)) {
                    menuToggle.setAttribute("aria-expanded", "false");
                    menuToggle.classList.remove("active");
                    navMenu.classList.remove("active");
                }
            });
        }

        // ---------------------------------------------------------------------
        // 7. SCROLL PROGRESS BAR
        // ---------------------------------------------------------------------
        const scrollProgressBar = document.getElementById("scroll-progress");
        if (scrollProgressBar) {
            window.addEventListener("scroll", () => {
                if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

                const winScroll = document.documentElement.scrollTop || document.body.scrollTop;
                const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
                if (height > 0) {
                    const scrolled = (winScroll / height) * 100;
                    scrollProgressBar.style.width = Math.min(100, Math.max(0, scrolled)) + "%";
                }
            }, { passive: true });
        }

        // ---------------------------------------------------------------------
        // 8. INTERSECTION OBSERVER FOR SCROLL REVEALS
        // ---------------------------------------------------------------------
        const revealElements = document.querySelectorAll(".reveal");

        const revealCallback = (entries, observer) => {
            const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    if (prefersReduced) {
                        entry.target.classList.add("revealed");
                        observer.unobserve(entry.target);
                        return;
                    }

                    const parent = entry.target.parentElement;
                    if (parent) {
                        const siblings = Array.from(parent.querySelectorAll(".reveal"));
                        const isStaggeredGroup = siblings.length > 1 && (
                            entry.target.classList.contains("contact-card") ||
                            entry.target.classList.contains("venture-row")
                        );

                        if (isStaggeredGroup) {
                            const index = siblings.indexOf(entry.target);
                            setTimeout(() => {
                                entry.target.classList.add("revealed");
                            }, index * 120);
                        } else {
                            entry.target.classList.add("revealed");
                        }
                    } else {
                        entry.target.classList.add("revealed");
                    }

                    observer.unobserve(entry.target);
                }
            });
        };

        const revealObserver = new IntersectionObserver(revealCallback, {
            root: null,
            threshold: 0.1,
            rootMargin: "0px 0px -50px 0px"
        });

        revealElements.forEach(el => {
            if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
                el.classList.add("revealed");
            } else {
                revealObserver.observe(el);
            }
        });

        // Motion preference changes
        window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", () => {
            const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
            if (prefersReduced) {
                revealElements.forEach(el => el.classList.add("revealed"));
                if (scrollProgressBar) scrollProgressBar.style.width = "0%";
            }
        });

        // ---------------------------------------------------------------------
        // 9. HIGH-SECURITY FORM SUBMISSION ENGINE
        // ---------------------------------------------------------------------
        const contactForm = document.getElementById("contact-form");
        const submitBtn = document.getElementById("form-submit");
        const formStatus = document.getElementById("form-status");

        if (contactForm && submitBtn && formStatus) {
            contactForm.addEventListener("submit", async (e) => {
                e.preventDefault();

                // DEFENSE 1: Honeypot trap check
                const honeypot = document.getElementById("honeypot");
                if (honeypot && honeypot.value.trim() !== "") {
                    // Bot trapped: silently simulate success and drop payload
                    formStatus.className = "form-status success";
                    formStatus.textContent = "Message sent successfully!";
                    contactForm.reset();
                    return;
                }

                // DEFENSE 2: Human Time-Gate Challenge
                const elapsedSinceLoad = Date.now() - PAGE_INIT_TIMESTAMP;
                if (elapsedSinceLoad < SECURITY_CONFIG.MIN_SUBMISSION_TIME_MS) {
                    // Automated headless agent submitted faster than humanly possible
                    formStatus.className = "form-status error";
                    formStatus.textContent = "Submission rejected: Automated submission detected. Please take a moment to review your message.";
                    return;
                }

                // DEFENSE 3: Rate Limiting & Cooldown Verification
                const rateCheck = checkRateLimit();
                if (!rateCheck.allowed) {
                    formStatus.className = "form-status error";
                    formStatus.textContent = rateCheck.reason;
                    return;
                }

                // DEFENSE 4: Form Action URL & Protocol Integrity Check
                const rawActionUrl = contactForm.getAttribute("action") || "";
                if (!rawActionUrl.startsWith(SECURITY_CONFIG.ALLOWED_FORM_ACTION_PREFIX)) {
                    formStatus.className = "form-status error";
                    formStatus.textContent = "Security validation error: Unauthorized form action endpoint.";
                    return;
                }

                if (rawActionUrl.includes("YOUR_ENDPOINT_ID")) {
                    formStatus.className = "form-status error";
                    formStatus.textContent = "Setup required: The Formspree endpoint ID has not been configured yet. Please reach out via direct email.";
                    return;
                }

                // DEFENSE 5: Input Sanitization & Boundary Validation
                const nameInput = document.getElementById("name");
                const emailInput = document.getElementById("email");
                const subjectInput = document.getElementById("subject");
                const messageInput = document.getElementById("message");

                const cleanName = sanitizeText(nameInput ? nameInput.value : "", SECURITY_CONFIG.FIELD_LIMITS.NAME_MAX);
                const cleanEmail = sanitizeText(emailInput ? emailInput.value : "", SECURITY_CONFIG.FIELD_LIMITS.EMAIL_MAX);
                const cleanSubject = sanitizeText(subjectInput ? subjectInput.value : "", SECURITY_CONFIG.FIELD_LIMITS.SUBJECT_MAX);
                const cleanMessage = sanitizeText(messageInput ? messageInput.value : "", SECURITY_CONFIG.FIELD_LIMITS.MESSAGE_MAX);

                if (!isValidName(cleanName)) {
                    formStatus.className = "form-status error";
                    formStatus.textContent = "Invalid name: Please provide a valid name (2-100 characters, no forbidden characters).";
                    if (nameInput) nameInput.focus();
                    return;
                }

                if (!isValidEmail(cleanEmail)) {
                    formStatus.className = "form-status error";
                    formStatus.textContent = "Invalid email: Please provide a valid email address.";
                    if (emailInput) emailInput.focus();
                    return;
                }

                if (cleanMessage.length < SECURITY_CONFIG.FIELD_LIMITS.MESSAGE_MIN) {
                    formStatus.className = "form-status error";
                    formStatus.textContent = `Message too short: Minimum ${SECURITY_CONFIG.FIELD_LIMITS.MESSAGE_MIN} characters required.`;
                    if (messageInput) messageInput.focus();
                    return;
                }

                // Prepare Sanitized Payload
                const sanitizedData = new FormData();
                sanitizedData.append("name", cleanName);
                sanitizedData.append("email", cleanEmail);
                if (cleanSubject) sanitizedData.append("subject", cleanSubject);
                sanitizedData.append("message", cleanMessage);

                // UI State Update
                submitBtn.disabled = true;
                const originalBtnText = submitBtn.textContent;
                submitBtn.textContent = "Sending...";
                formStatus.className = "form-status";
                formStatus.textContent = "";

                try {
                    const response = await fetch(rawActionUrl, {
                        method: "POST",
                        body: sanitizedData,
                        headers: {
                            "Accept": "application/json"
                        }
                    });

                    if (response.ok) {
                        recordSubmission(rateCheck.history);
                        formStatus.className = "form-status success";
                        formStatus.textContent = "Message transmitted successfully! Thank you.";
                        contactForm.reset();
                    } else {
                        const data = await response.json();
                        formStatus.className = "form-status error";
                        if (data && Array.isArray(data.errors) && data.errors.length > 0) {
                            // Safe textContent assignment (Zero DOM-XSS risk)
                            formStatus.textContent = data.errors.map(err => sanitizeText(err.message, 200)).join(", ");
                        } else {
                            formStatus.textContent = "Transmission failed: Unable to deliver message. Please contact via direct email.";
                        }
                    }
                } catch (error) {
                    formStatus.className = "form-status error";
                    formStatus.textContent = "Network error: Transmission interrupted. Please check your connection or email directly.";
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                }
            });
        }
    });
})();
