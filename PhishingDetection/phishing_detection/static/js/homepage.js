document.addEventListener("DOMContentLoaded", () => {

/* ---------- Translations ---------- */
const translations = {
    en: {
        "site.title1": "PhishGuard AI — Home",
        "site.title2": "PhishGuard AI — Live Dashboard",
        "site.title3": "PhishGuard AI — Features",
        "site.title4": "PhishGuard AI — About Us",
        "site.title5": "PhishGuard AI — Contact Us",
        "site.title6": "PhishGuard AI — FAQ",
        "site.title7": "PhishGuard AI — Settings",
        "site.title8": "PhishGuard AI — Watch Demo",
        "brand.name": "PhishGuard AI",
        "nav.home": "Home",
        "nav.live": "Live Dashboard",
        "nav.features": "Features",
        "nav.contact": "Contact Us",
        "nav.about": "About Us",
        "nav.faq": "FAQ",
        "nav.settings": "Settings",
        "nav.getStarted": "Get Started",
        "hero.title": "Advanced AI-Powered URL Phishing Detection",
        "hero.desc": "Protect your organization with real-time URL scanning, machine learning analysis, and instant alerts. Stop malicious websites before users can access them.",
        "hero.try": "Try URL Scanner",
        "hero.watch": "Watch Demo",
        "scanner.title": "Try Our AI URL Scanner",
        "scanner.label": "Enter URL to scan:",
        "scanner.scan": "Scan URL with AI",
        "footer.tagline": "Advanced AI-powered phishing detection and protection for modern enterprises.",
        "footer.product": "Product",
        "footer.company": "Company",
        "footer.support": "Support",

        "panel.title": "Accessibility",
        "panel.close": "Close",
        "panel.reset": "Reset to defaults",
        "panel.darkMode": "🌙 Dark Mode",
        "panel.darkModeDesc": "Reduce glare for low-light environments",
        "panel.largeText": "📝 Large Text",
        "panel.largeTextDesc": "Increase base text size for readability",
        "panel.readableFont": "📖 Readable Font",
        "panel.readableFontDesc": "Use a simple, easier-to-read typeface",
        "panel.fontSize": "Font Size",

        "live.title": "Live Threat Detection Dashboard",
        "live.desc": "Real-time monitoring and instant alerts for your security team",
        "live.security": "Security Operations Center",
        "live.monitor": "Live Monitoring Active",
        "live.block": "Threat Block Today",
        "live.detect": "Detection Accuracy",
        "live.response": "Response Time",
        "live.monitor": "Active Monitors",
        "live.level": "Threat Level Distribution",
        "live.threat": "Live Threats Alerts",

        "features.title": "Powerful AI Protection Features",
        "features.aiTitle": "Advanced AI Analysis",
        "features.aiDesc": "Machine learning algorithms analyze URL structure, domain reputation, and content patterns to detect sophisticated phishing websites and malicious links.",
        "features.realTimeTitle": "Real-time Protection",
        "features.realTimeDesc": "Instant threat detection and blocking with sub-second response times. Protect your users before they can interact with malicious content.",
        "features.analyticsTitle": "Comprehensive Analytics",
        "features.analyticsDesc": "Detailed reporting and analytics dashboard with threat intelligence, user behavior insights, and security metrics.",
        "features.urlScanTitle": "URL Scanning",
        "features.urlScanDesc": "Real-time URL analysis and reputation checking. Automatically quarantine suspicious links and domains.",
        "features.trainingTitle": "User Training",
        "features.trainingDesc": "Automated security awareness training with simulated phishing campaigns and personalized learning paths.",
        "features.integrationTitle": "Easy Integration",
        "features.integrationDesc": "Seamless integration with existing email systems, security tools, and enterprise infrastructure via APIs.",

        "about.title": "About PhishGuard AI",
        "about.desc": "PhishGuard AI is an advanced phishing detection platform that leverages artificial intelligence to protect users from malicious websites and online scams in real time.",
        "about.mvTitle": "Our Mission & Vision",
        "about.missionTitle": "Our Mission",
        "about.missionDesc": "To provide reliable, AI-driven cybersecurity tools that are accessible, proactive, and easy to use — ensuring safety for businesses, students, and everyday users across the world.",
        "about.visionTitle": "Our Vision",
        "about.visionDesc": "To become the most trusted AI-driven cybersecurity solution, safeguarding digital experiences globally.",
        "about.whyTitle": "Why Choose Us?",
        "about.aiTitle": "AI-Powered Detection",
        "about.aiDesc": "Our system uses machine learning models to analyze URLs, detect phishing attempts, and provide real-time protection.",
        "about.uiTitle": "User-Friendly",
        "about.uiDesc": "PhishGuard AI features a simple and intuitive interface, making security accessible for everyone regardless of technical skills.",
        "about.alertTitle": "Real-Time Alerts",
        "about.alertDesc": "We provide instant alerts and notifications to ensure users are always protected online.",
        "about.teamTitle": "Meet the Creators",
        "about.farisRole": "Project Manager",
        "about.farisDesc": "Coordinates development tasks and ensures smooth collaboration across the team.",
        "about.afiffRole": "UI/UX Designer",
        "about.afiffDesc": "Focuses on creating intuitive, user-friendly interfaces for enhanced usability.",
        "about.imanRole": "Lead Developer",
        "about.imanDesc": "Specializes in backend security and AI model integration for phishing detection.",

        "contact.title": "Contact Us",
        "contact.desc": "Have questions or want a demo? Fill out the form below and our security team will reach out.",
        "contact.officeTitle": "📍 Our Office",
        "contact.officeAddress": "MCMC HQ Tower 1<br>Jalan Impact, Cyber 6<br>63000 Cyberjaya, Selangor, Malaysia",
        "contact.phoneTitle": "📞 Call Us",
        "contact.phoneInfo": "+60 3-8688 8000<br>+60 13-393 9781<br>+60 13-675 3705<br>+60 11-7078 7650<br>Monday–Friday, 9:00 AM – 6:00 PM",
        "contact.emailTitle": "✉️ Email",
        "contact.emailInfo": "support@phishguard.ai<br>sales@phishguard.ai",
        "contact.form.name": "Full Name",
        "contact.form.email": "Email",
        "contact.form.phone": "Phone",
        "contact.form.message": "Message",
        "contact.form.submit": "Send Message",

        "faq.title": "Frequently Asked Questions",
        "faq.desc": "Find answers to the most common questions about PhishGuard AI.",
        "faq.q1": "What is PhishGuard AI?",
        "faq.a1": "PhishGuard AI is an AI-powered phishing detection system that analyzes URLs in real-time to block malicious threats before they reach users.",
        "faq.q2": "How accurate is the AI detection?",
        "faq.a2": "Our models achieve over 99% detection accuracy using machine learning, threat intelligence feeds, and continuously updated data sources.",
        "faq.q3": "Can I integrate PhishGuard with my existing security system?",
        "faq.a3": "Yes! We offer REST APIs and webhook-based integration for SIEMs, email security gateways, and proxy firewalls.",
        "faq.q4": "Do you offer enterprise support?",
        "faq.a4": "Absolutely. Our enterprise plans include 24/7 monitoring, dedicated support engineers, and SLA-backed uptime guarantees.",
        "faq.q5": "Is user training available?",
        "faq.a5": "Yes! We include phishing simulation campaigns and educational dashboards to improve employee awareness.",

        "settings.title": "Website Settings",
        "settings.languageTitle": "🌐 Language & Region",
        "settings.languageLabel": "Select Language:",
        "settings.accessibilityTitle": "🧠 Accessibility & Appearance",
        "settings.darkMode": "Dark Mode",
        "settings.largeText": "Large Text",
        "settings.readableFont": "Readable Font",
        "settings.fontSize": "Font Size",
        "settings.locationTitle": "📍 Location",
        "settings.generalTitle": "🧰 General",
        "settings.reset": "Reset to Default",
        "settings.about": "About this website: A simple, fast, and accessible platform built for everyone.",
        "font.sm": "Small",
        "font.md": "Medium",
        "font.lg": "Large",

        "demo.title": "Phish Guard AI Demo"
    },

    my: {
        "site.title1": "PhishGuard AI — Laman Utama",
        "site.title2": "PhishGuard AI - Papan Pemuka Langsung",
        "site.title3": "PhishGuard AI — Ciri-ciri",
        "site.title4": "PhishGuard AI — Tentang Kami",
        "site.title5": "PhishGuard AI — Hubungi Kami",
        "site.title6": "PhishGuard AI — Soalan Lazim",
        "site.title7": "PhishGuard AI — Tetapan",
        "site.title8": "PhishGuard AI — Tonton Demo",
        "brand.name": "PhishGuard AI",
        "nav.home": "Laman Utama",
        "nav.live": "Papan Pemuka Langsung",
        "nav.features": "Ciri-ciri",
        "nav.contact": "Hubungi Kami",
        "nav.about": "Tentang Kami",
        "nav.faq": "Soalan Lazim",
        "nav.settings": "Tetapan",
        "nav.getStarted": "Mula",
        "hero.title": "Pengesanan Phishing URL Berkuasa AI",
        "hero.desc": "Lindungi organisasi anda dengan pengimbasan URL masa nyata, analisis pembelajaran mesin, dan amaran segera. Hentikan laman web berbahaya sebelum pengguna mengaksesnya.",
        "hero.try": "Cuba Pengimbas URL",
        "hero.watch": "Tonton Demo",
        "scanner.title": "Cuba Pengimbas URL AI Kami",
        "scanner.label": "Masukkan URL untuk imbas:",
        "scanner.scan": "Imbas URL dengan AI",
        "footer.tagline": "Pengesanan phishing berkuasa AI untuk perusahaan moden.",
        "footer.product": "Produk",
        "footer.company": "Syarikat",
        "footer.support": "Sokongan",

        "panel.title": "Kebolehcapaian",
        "panel.close": "Tutup",
        "panel.reset": "Tetapkan semula ke asal",
        "panel.darkMode": "🌙 Mod Gelap",
        "panel.darkModeDesc": "Kurangkan silau untuk persekitaran kurang cahaya",
        "panel.largeText": "📝 Teks Besar",
        "panel.largeTextDesc": "Besarkan saiz teks untuk lebih mudah dibaca",
        "panel.readableFont": "📖 Fon Mudah Baca",
        "panel.readableFontDesc": "Guna fon yang lebih ringkas dan mudah dibaca",
        "panel.fontSize": "Saiz Fon",

        "live.title": "Papan Pemuka Pengesanan Ancaman Secara Langsung",
        "live.desc": "Pemantauan masa nyata dan amaran segera untuk pasukan keselamatan anda",
        "live.security": "Pusat Operasi Keselamatan",
        "live.monitor": "Pemantauan Langsung Aktif",
        "live.block": "Ancaman Dihalang Hari Ini",
        "live.detect": "Ketepatan Pengesanan",
        "live.response": "Masa Tindak Balas",
        "live.monitor": "Pemantau Aktif",
        "live.level": "Taburan Tahap Ancaman",
        "live.threat": "Amaran Ancaman Langsung",

        "features.title": "Ciri Perlindungan AI yang Berkuasa",
        "features.aiTitle": "Analisis AI Lanjutan",
        "features.aiDesc": "Algoritma pembelajaran mesin menganalisis struktur URL, reputasi domain dan corak kandungan untuk mengesan laman web pancingan data yang canggih dan pautan berbahaya.",
        "features.realTimeTitle": "Perlindungan Masa Nyata",
        "features.realTimeDesc": "Pengesanan ancaman serta-merta dan penyekatan dengan masa tindak balas sub-saat. Lindungi pengguna anda sebelum mereka berinteraksi dengan kandungan berbahaya.",
        "features.analyticsTitle": "Analitik Menyeluruh",
        "features.analyticsDesc": "Laporan terperinci dan papan pemuka analitik dengan risikan ancaman, cerapan tingkah laku pengguna dan metrik keselamatan.",
        "features.urlScanTitle": "Imbasan URL",
        "features.urlScanDesc": "Analisis URL masa nyata dan semakan reputasi. Kuarantin secara automatik pautan dan domain yang mencurigakan.",
        "features.trainingTitle": "Latihan Pengguna",
        "features.trainingDesc": "Latihan kesedaran keselamatan automatik dengan kempen pancingan data simulasi dan laluan pembelajaran diperibadikan.",
        "features.integrationTitle": "Integrasi Mudah",
        "features.integrationDesc": "Integrasi lancar dengan sistem e-mel sedia ada, alatan keselamatan, dan infrastruktur perusahaan melalui API.",

        "about.title": "Tentang PhishGuard AI",
        "about.desc": "PhishGuard AI ialah platform pengesanan phishing canggih yang menggunakan kecerdasan buatan untuk melindungi pengguna daripada laman web berbahaya dan penipuan dalam talian secara masa nyata.",
        "about.mvTitle": "Misi & Visi Kami",
        "about.missionTitle": "Misi Kami",
        "about.missionDesc": "Memberi alat keselamatan siber berasaskan AI yang boleh dipercayai, proaktif, dan mudah digunakan — memastikan keselamatan untuk perniagaan, pelajar dan pengguna di seluruh dunia.",
        "about.visionTitle": "Visi Kami",
        "about.visionDesc": "Menjadi penyelesaian keselamatan siber berasaskan AI yang paling dipercayai, melindungi pengalaman digital di seluruh dunia.",
        "about.whyTitle": "Kenapa Pilih Kami?",
        "about.aiTitle": "Pengesanan Dikuasakan AI",
        "about.aiDesc": "Sistem kami menggunakan model pembelajaran mesin untuk menganalisis URL, mengesan cubaan phishing, dan memberi perlindungan masa nyata.",
        "about.uiTitle": "Mesra Pengguna",
        "about.uiDesc": "PhishGuard AI mempunyai antara muka yang mudah dan intuitif, menjadikan keselamatan boleh diakses oleh semua tanpa mengira kemahiran teknikal.",
        "about.alertTitle": "Amaran Masa Nyata",
        "about.alertDesc": "Kami menyediakan amaran dan notifikasi segera untuk memastikan pengguna sentiasa dilindungi dalam talian.",
        "about.teamTitle": "Kenali Pencipta Kami",
        "about.farisRole": "Pengurus Projek",
        "about.farisDesc": "Menyelaras tugasan pembangunan dan memastikan kerjasama pasukan berjalan lancar.",
        "about.afiffRole": "Pereka UI/UX",
        "about.afiffDesc": "Menumpukan kepada penciptaan antara muka yang mesra pengguna untuk meningkatkan kebolehgunaan.",
        "about.imanRole": "Ketua Pembangun",
        "about.imanDesc": "Pakar dalam keselamatan backend dan integrasi model AI untuk pengesanan phishing.",

        "contact.title": "Hubungi Kami",
        "contact.desc": "Ada pertanyaan atau ingin demo? Isikan borang di bawah dan pasukan keselamatan kami akan menghubungi anda.",
        "contact.officeTitle": "📍 Pejabat Kami",
        "contact.officeAddress": "MCMC HQ Tower 1<br>Jalan Impact, Cyber 6<br>63000 Cyberjaya, Selangor, Malaysia",
        "contact.phoneTitle": "📞 Telefon",
        "contact.phoneInfo": "+60 3-1234 5678<br>+60 12-345 6789<br>+60 13-675 3705<br>+60 11-7078 7650<br>Isnin–Jumaat, 9:00 AM – 6:00 PM",
        "contact.emailTitle": "✉️ Emel",
        "contact.emailInfo": "support@phishguard.ai<br>sales@phishguard.ai",
        "contact.form.name": "Nama Penuh",
        "contact.form.email": "Emel",
        "contact.form.phone": "Telefon",
        "contact.form.message": "Mesej",
        "contact.form.submit": "Hantar Mesej",

        "faq.title": "Soalan Lazim",
        "faq.desc": "Cari jawapan kepada soalan yang paling biasa tentang PhishGuard AI.",
        "faq.q1": "Apakah PhishGuard AI?",
        "faq.a1": "PhishGuard AI ialah sistem pengesanan phishing berkuasa AI yang menganalisis URL secara masa nyata untuk menyekat ancaman sebelum sampai kepada pengguna.",
        "faq.q2": "Berapakah tepat pengesanan AI?",
        "faq.a2": "Model kami mencapai lebih 99% ketepatan pengesanan menggunakan pembelajaran mesin, suapan intelijen ancaman, dan data yang sentiasa dikemas kini.",
        "faq.q3": "Bolehkah saya mengintegrasikan PhishGuard dengan sistem keselamatan sedia ada?",
        "faq.a3": "Ya! Kami menawarkan REST API dan integrasi berasaskan webhook untuk SIEM, pintu gerbang e-mel keselamatan, dan firewall proksi.",
        "faq.q4": "Adakah anda menawarkan sokongan perusahaan?",
        "faq.a4": "Sudah tentu. Pelan perusahaan kami termasuk pemantauan 24/7, jurutera sokongan khusus, dan jaminan masa operasi SLA.",
        "faq.q5": "Adakah latihan pengguna disediakan?",
        "faq.a5": "Ya! Kami menyertakan kempen simulasi phishing dan papan pemuka pendidikan untuk meningkatkan kesedaran pekerja.",

        "settings.title": "Tetapan Laman Web",
        "settings.languageTitle": "🌐 Bahasa & Wilayah",
        "settings.languageLabel": "Pilih Bahasa:",
        "settings.accessibilityTitle": "🧠 Kebolehcapaian & Penampilan",
        "settings.darkMode": "Mod Gelap",
        "settings.largeText": "Teks Besar",
        "settings.readableFont": "Fon Mudah Dibaca",
        "settings.fontSize": "Saiz Fon",
        "settings.locationTitle": "📍 Lokasi",
        "settings.locationDesc": "Pejabat utama kami terletak di:",
        "settings.address": "123, Jalan Contoh, Kuala Lumpur, Malaysia",
        "settings.generalTitle": "🧰 Umum",
        "settings.reset": "Tetapkan Semula",
        "settings.about": "Tentang laman ini: Platform pantas dan mudah diakses untuk semua.",
        "font.sm": "Kecil",
        "font.md": "Sederhana",
        "font.lg": "Besar",

        "demo.title": "Demo PhishGuard AI"
    }
};

    /* ---------- DOM helpers ---------- */
    const $ = s => document.querySelector(s);
    const $$ = s => Array.from(document.querySelectorAll(s));

    // set year
    const yearEl = $('#year');
    if (yearEl) yearEl.textContent = new Date().getFullYear();

    /* ---------- Language selector ---------- */
    const langSelect = $('#langSelect');
    const langToggle = $('#langToggle');
    const langOptions = $('#langOptions');
    const langLabel = $('#langLabel');

    function translatePage(lang) {
    const map = translations[lang] || translations.en;
    $$('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (map[key]) el.innerHTML = map[key];
    });
}

    function toggleFAQ(id) {
    const answer = document.getElementById(`answer-${id}`);
    const icon = document.getElementById(`icon-${id}`);
    if (!answer || !icon) return;

    const isHidden = answer.classList.contains('hidden');

    // Hide all answers
    document.querySelectorAll('[id^="answer-"]').forEach(a => a.classList.add('hidden'));
    document.querySelectorAll('[id^="icon-"]').forEach(i => i.textContent = '+');

    // Toggle the clicked one
    if (isHidden) {
        answer.classList.remove('hidden');
        icon.textContent = '−'; // change + to −
    }
}

    const savedLang = localStorage.getItem('phishguard_lang') || 'en';
    if (langLabel) langLabel.textContent = (savedLang === 'my') ? '🇲🇾 Bahasa Melayu' : '🇺🇸 English';
    translatePage(savedLang);

    if (langToggle && langOptions) {
        langToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            const open = langOptions.classList.toggle('open');
            langToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
    }
    // choose language (defensive)
    if (langOptions) {
        langOptions.querySelectorAll('button[data-lang]').forEach(btn => {
            btn.addEventListener('click', () => {
                const lang = btn.getAttribute('data-lang');
                localStorage.setItem('phishguard_lang', lang);
                if (langLabel) langLabel.textContent = (lang === 'my') ? '🇲🇾 Bahasa Melayu' : '🇺🇸 English';
                langOptions.classList.remove('open');
                if (langToggle) langToggle.setAttribute('aria-expanded', 'false');
                translatePage(lang);
            });
        });
    }
    // close language dropdown on outside click
    document.addEventListener('click', (e) => {
        if (langSelect && !langSelect.contains(e.target)) {
            langOptions && langOptions.classList.remove('open');
            langToggle && langToggle.setAttribute('aria-expanded', 'false');
        }
    });

    /* ---------- Dark mode ---------- */
    const darkToggle = $('#darkToggle');
    const panelDarkToggle = $('#panelDarkToggle');
    const darkThumb = $('#darkThumb');
    const DARK_KEY = 'phishguard_dark';

    function setDark(enabled) {
        document.body.classList.toggle('dark-gray', enabled);
        if (darkToggle) darkToggle.checked = enabled;
        if (panelDarkToggle) panelDarkToggle.checked = enabled;
        // move thumb visually when present
        if (darkThumb) darkThumb.style.transform = enabled ? 'translateX(20px)' : 'translateX(0)';
        if (enabled) localStorage.setItem(DARK_KEY, '1'); else localStorage.removeItem(DARK_KEY);
    }
    // initialize
    setDark(!!localStorage.getItem(DARK_KEY));

    if (darkToggle) darkToggle.addEventListener('change', (e) => setDark(e.target.checked));
    if (panelDarkToggle) panelDarkToggle.addEventListener('change', (e) => setDark(e.target.checked));

    /* ---------- Accessibility panel (open/close) ---------- */
    const accessBtn = $('#accessBtn');
    const accessPanel = $('#accessPanel');
    const accessClose = $('#accessClose');

    function openAccess() {
        accessPanel && accessPanel.classList.add('open');
        accessPanel && accessPanel.setAttribute('aria-hidden', 'false');
        accessClose && accessClose.focus();
    }
    function closeAccess() {
        accessPanel && accessPanel.classList.remove('open');
        accessPanel && accessPanel.setAttribute('aria-hidden', 'true');
        accessBtn && accessBtn.focus();
    }
    accessBtn && accessBtn.addEventListener('click', openAccess);
    accessClose && accessClose.addEventListener('click', closeAccess);
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && accessPanel && accessPanel.classList.contains('open')) closeAccess();
    });

    // keyboard open for floating button
    accessBtn && accessBtn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openAccess(); }
    });

    // close panel when clicking outside
    document.addEventListener('click', (e) => {
        if (accessPanel && accessPanel.classList.contains('open') && !accessPanel.contains(e.target) && !accessBtn.contains(e.target)) {
            closeAccess();
        }
    });

    // trap focus in panel (basic)
    accessPanel && accessPanel.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') {
            const focusable = accessPanel.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];

            if (e.shiftKey) {
                if (document.activeElement === first) {
                    e.preventDefault();
                    last.focus();
                }
            } else {
                if (document.activeElement === last) {
                    e.preventDefault();
                    first.focus();
                }
            }
        }
    });

    /* ---------- Accessibility toggles ---------- */
    const toggleArial = $('#toggleArial'); // readable font
    const toggleLargeText = $('#toggleLargeText'); // large text
    const fontInc = $('#fontInc');
    const fontDec = $('#fontDec');
    const fontReset = $('#fontReset');

    // Font scaling: adjust root font-size (rem base)
    let fontScale = 1.0;
    function applyFontScale() {
        document.documentElement.style.fontSize = fontScale + 'rem';
    }
    // restore saved
    const savedScale = localStorage.getItem('phishguard_fontScale');
    if (savedScale) { fontScale = parseFloat(savedScale) || 1.0; applyFontScale(); }

    fontInc && fontInc.addEventListener('click', () => {
        fontScale = Math.min(1.6, +(fontScale + 0.1).toFixed(2));
        applyFontScale();
        localStorage.setItem('phishguard_fontScale', fontScale);
    });
    fontDec && fontDec.addEventListener('click', () => {
        fontScale = Math.max(0.8, +(fontScale - 0.1).toFixed(2));
        applyFontScale();
        localStorage.setItem('phishguard_fontScale', fontScale);
    });
    fontReset && fontReset.addEventListener('click', () => {
        fontScale = 1.0; applyFontScale();
        localStorage.removeItem('phishguard_fontScale');
    });

    // Large text toggle
    function setLargeText(enabled) {
        document.body.classList.toggle('large-text', enabled);
        if (toggleLargeText) toggleLargeText.checked = enabled;
        if (enabled) localStorage.setItem('phishguard_largeText', '1'); else localStorage.removeItem('phishguard_largeText');
    }
    setLargeText(!!localStorage.getItem('phishguard_largeText'));
    toggleLargeText && toggleLargeText.addEventListener('change', (e) => setLargeText(e.target.checked));

    // Readable font toggle
    function setReadableFont(enabled) {
        document.body.classList.toggle('dyslexia-font', enabled);
        if (toggleArial) toggleArial.checked = enabled;
        if (enabled) localStorage.setItem('phishguard_readableFont', '1'); else localStorage.removeItem('phishguard_readableFont');
    }
    setReadableFont(!!localStorage.getItem('phishguard_readableFont'));
    toggleArial && toggleArial.addEventListener('change', (e) => setReadableFont(e.target.checked));

    // Reset accessibility defaults
    const accessReset = $('#accessReset');
    accessReset && accessReset.addEventListener('click', () => {
        setDark(false);
        setLargeText(false);
        setReadableFont(false);
        fontScale = 1.0; applyFontScale();
        if (panelDarkToggle) panelDarkToggle.checked = false;
        if (darkToggle) darkToggle.checked = false;
        if (toggleLargeText) toggleLargeText.checked = false;
        if (toggleArial) toggleArial.checked = false;
        localStorage.removeItem('phishguard_dark');
        localStorage.removeItem('phishguard_largeText');
        localStorage.removeItem('phishguard_readableFont');
        localStorage.removeItem('phishguard_fontScale');
    });

    // Ensure base font scale applied
    applyFontScale();

    /* ---------- SETTINGS PAGE SYNC ---------- */

// references
const settingLang = $('#language');
const settingDark = document.querySelector('input#fontToggle:nth-of-type(1)');
const settingLargeText = document.querySelectorAll('#fontToggle')[1];
const settingReadable = document.querySelectorAll('#fontToggle')[2];
const settingFontSize = $('#textSize');
const resetButton = $('#resetButton');

/* ----- 1. Language & Region sync ----- */
if (settingLang) {
  // initialize dropdown
  const savedLang2 = localStorage.getItem('phishguard_lang') || 'en';
  settingLang.value = savedLang2 === 'my' ? 'bm' : 'en';

  // update when user changes language from settings
  settingLang.addEventListener('change', () => {
    const newLang = settingLang.value === 'bm' ? 'my' : 'en';
    localStorage.setItem('phishguard_lang', newLang);
    translatePage(newLang);
    if (langLabel) langLabel.textContent = (newLang === 'my') ? '🇲🇾 Bahasa Melayu' : '🇺🇸 English';
  });
}

/* ----- 2. Accessibility sync (Dark Mode, Large Text, Readable Font) ----- */

// initialize states based on saved preferences
if (settingDark) settingDark.checked = !!localStorage.getItem('phishguard_dark');
if (settingLargeText) settingLargeText.checked = !!localStorage.getItem('phishguard_largeText');
if (settingReadable) settingReadable.checked = !!localStorage.getItem('phishguard_readableFont');

// event listeners for real-time sync
if (settingDark) {
  settingDark.addEventListener('change', e => setDark(e.target.checked));
}
if (settingLargeText) {
  settingLargeText.addEventListener('change', e => setLargeText(e.target.checked));
}
if (settingReadable) {
  settingReadable.addEventListener('change', e => setReadableFont(e.target.checked));
}

/* ----- 3. Font size sync with accessibility ----- */
if (settingFontSize) {
  // Load saved font scale
  const savedScale2 = parseFloat(localStorage.getItem('phishguard_fontScale')) || 1.0;
  fontScale = savedScale2;
  applyFontScale();

  // Update dropdown visually
  updateFontDropdown(fontScale);

  // When user changes dropdown manually
  settingFontSize.addEventListener('change', () => {
    switch (settingFontSize.value) {
      case 'sm': fontScale = 0.9; break;
      case 'md': fontScale = 1.0; break;
      case 'lg': fontScale = 1.3; break;
    }
    applyFontScale();
    localStorage.setItem('phishguard_fontScale', fontScale);
  });
}

// Helper to update dropdown when accessibility buttons pressed
function updateFontDropdown(scale) {
  if (!settingFontSize) return;
  if (scale <= 0.95) settingFontSize.value = 'sm';
  else if (scale >= 1.25) settingFontSize.value = 'lg';
  else settingFontSize.value = 'md';
}

// Modify the accessibility buttons to also update dropdown
if (fontInc) {
  fontInc.addEventListener('click', () => {
    fontScale = Math.min(1.6, +(fontScale + 0.1).toFixed(2));
    applyFontScale();
    localStorage.setItem('phishguard_fontScale', fontScale);
    updateFontDropdown(fontScale);
  });
}
if (fontDec) {
  fontDec.addEventListener('click', () => {
    fontScale = Math.max(0.8, +(fontScale - 0.1).toFixed(2));
    applyFontScale();
    localStorage.setItem('phishguard_fontScale', fontScale);
    updateFontDropdown(fontScale);
  });
}
if (fontReset) {
  fontReset.addEventListener('click', () => {
    fontScale = 1.0;
    applyFontScale();
    localStorage.removeItem('phishguard_fontScale');
    updateFontDropdown(fontScale);
  });
}

/* ----- 4. Reset to default sync ----- */
if (resetButton) {
  resetButton.addEventListener('click', () => {
    // reset accessibility
    setDark(false);
    setLargeText(false);
    setReadableFont(false);
    fontScale = 1.0;
    applyFontScale();

    // reset checkboxes
    if (settingDark) settingDark.checked = false;
    if (settingLargeText) settingLargeText.checked = false;
    if (settingReadable) settingReadable.checked = false;
    if (settingFontSize) settingFontSize.value = 'md';

    // reset language
    localStorage.setItem('phishguard_lang', 'en');
    translatePage('en');
    if (langLabel) langLabel.textContent = '🇺🇸 English';
    if (settingLang) settingLang.value = 'en';

    // remove all localStorage prefs
    localStorage.removeItem('phishguard_dark');
    localStorage.removeItem('phishguard_largeText');
    localStorage.removeItem('phishguard_readableFont');
    localStorage.removeItem('phishguard_fontScale');

    alert('Settings have been reset to default.');
    });
}

  /* ---------- AI URL SCANNER ---------- */
  const form = document.getElementById("urlScanForm");
  const input = document.getElementById("urlInput");
  const resultBox = document.getElementById("scanResult");

  if (form && input && resultBox) {
    form.addEventListener("submit", async e => {
      e.preventDefault();
      const url = input.value.trim();
      if (!url) {
        resultBox.classList.remove("hidden");
        resultBox.innerHTML = "<p style='color:#b91c1c;'>⚠️ Please enter a URL.</p>";
        return;
      }

      resultBox.classList.remove("hidden");
      resultBox.innerHTML = "<p><center>🔍 Scanning...</center></p>";

      try {
        const res = await fetch("/predict", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        });
        const data = await res.json();

        if (data.result === "Phishing") {
          resultBox.innerHTML = "<p style='color:#dc2626;font-weight:600;'><center>🚨 Phishing Detected!</center></p>";
        } else if (data.result === "Legitimate") {
          resultBox.innerHTML = "<p style='color:#16a34a;font-weight:600;'><center>✅ Legitimate Website</center></p>";
        } else {
          resultBox.innerHTML = `<p style='color:#d97706;'>⚠️ ${data.detail || "Unknown result"}</p>`;
        }
      } catch {
        resultBox.innerHTML = "<p style='color:#b91c1c;'><center>❌ Error connecting to server.</center></p>";
      }
    });
  }

});

document.addEventListener("DOMContentLoaded", () => {
  // --- ELEMENTS ---
  const threatCountEl = document.getElementById("threatCount");
  const accuracyEl = document.getElementById("accuracyRate");
  const responseEl = document.getElementById("responseTime");
  const monitorsEl = document.getElementById("activeMonitors");
  const alertsFeed = document.getElementById("alertsFeed");
  const chartCanvas = document.getElementById("phishChart");

  // --- INITIAL DATA ---
  let threatsBlocked = 0;
  let detectionAccuracy = 99.6;
  let responseTime = 0.3;
  let activeMonitors = 1;

  // --- UPDATE UI FUNCTION ---
  function updateSOC() {
    threatCountEl.textContent = threatsBlocked;
    accuracyEl.textContent = detectionAccuracy.toFixed(1) + "%";
    responseEl.textContent = responseTime.toFixed(2) + "s";
    monitorsEl.textContent = activeMonitors;
  }

  // --- CHART SETUP ---
  const chartData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [{
      data: [0, 0, 0, 0],
      backgroundColor: ["#ef4444", "#f97316", "#facc15", "#22c55e"]
    }]
  };

  const chart = new Chart(chartCanvas, {
    type: "bar",
    data: chartData,
    options: {
      scales: {
        y: {
          beginAtZero: true,
          ticks: { color: "#e5e7eb" },
          grid: { color: "rgba(255,255,255,0.1)" }
        },
        x: {
          ticks: { color: "#e5e7eb" },
          grid: { display: false }
        }
      },
      plugins: { legend: { display: false } }
    }
  });

  // --- ADD ALERT FUNCTION ---
  function addAlert(url, result, time) {
    const color = result === "Phishing" ? "#ef4444" : "#22c55e";
    const div = document.createElement("div");
    div.className = "bg-gray-800 p-3 rounded-lg border-l-4";
    div.style.borderColor = color;
    div.innerHTML = `
      <p class="font-semibold text-white">${url}</p>
      <p class="text-sm text-gray-400">${time} — ${result}</p>
    `;
    alertsFeed.prepend(div);
    if (alertsFeed.children.length > 6)
      alertsFeed.removeChild(alertsFeed.lastChild);
  }

  // --- FETCH DATA FROM SERVER ---
  async function fetchThreat() {
    const startTime = performance.now(); // measure response time

    try {
      const res = await fetch("/get_latest_threat");
      const data = await res.json();
      const endTime = performance.now();

      // calculate response time
      responseTime = (endTime - startTime) / 1000;

      if (data.result && data.url) {
        if (data.result === "Phishing") {
          threatsBlocked++;
          detectionAccuracy = 99.0 + Math.random() * 0.7; // simulate accuracy
          chartData.datasets[0].data[0]++;
          chart.update();
          addAlert(data.url, data.result, data.time);
        } else if (data.result === "Legitimate") {
          detectionAccuracy = 99.2 + Math.random() * 0.6;
          addAlert(data.url, data.result, data.time);
        }

        // simulate active monitor increase every few threats
        if (threatsBlocked % 5 === 0) activeMonitors++;
      }

      updateSOC();
    } catch (e) {
      console.error("Failed to fetch:", e);
    }
  }

  // --- INIT ---
  updateSOC();
  setInterval(fetchThreat, 3000);
});