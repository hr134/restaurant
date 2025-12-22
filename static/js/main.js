/*
  Intersection Observer for Scroll Animations
*/
document.addEventListener("DOMContentLoaded", () => {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: "0px 0px -50px 0px"
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add("is-visible");
                observer.unobserve(entry.target); // Only animate once
            }
        });
    }, observerOptions);

    const animatedElements = document.querySelectorAll('.animate-on-scroll');
    animatedElements.forEach(el => observer.observe(el));

    // ------------------------------------------------
    // DARK MODE LOGIC
    // ------------------------------------------------
    const toggleBtn = document.getElementById("theme-toggle");
    const icon = toggleBtn.querySelector("i");
    const html = document.documentElement;

    // Load saved preference - Icon state only
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme === "dark") {
        if (icon) icon.classList.replace("bi-moon-stars-fill", "bi-sun-fill");
    }

    toggleBtn.addEventListener("click", () => {
        const currentTheme = html.getAttribute("data-theme");
        if (currentTheme === "dark") {
            html.removeAttribute("data-theme");
            localStorage.setItem("theme", "light");
            icon.classList.replace("bi-sun-fill", "bi-moon-stars-fill");
        } else {
            html.setAttribute("data-theme", "dark");
            localStorage.setItem("theme", "dark");
            icon.classList.replace("bi-moon-stars-fill", "bi-sun-fill");
        }
    });

    // ------------------------------------------------
    // PREMIUM FEATURES: SCROLL & NAVBAR
    // ------------------------------------------------
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('navbar-shrunk');
        } else {
            navbar.classList.remove('navbar-shrunk');
        }
    });

    // ------------------------------------------------
    // PREMIUM FEATURES: CUSTOM CURSOR
    // ------------------------------------------------
    const dot = document.querySelector('.cursor-dot');
    const outline = document.querySelector('.cursor-outline');
    let mouseX = 0, mouseY = 0;
    let dotX = 0, dotY = 0;
    let outlineX = 0, outlineY = 0;

    window.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
    });

    function animateCursor() {
        // Smoothly follow (lerp)
        dotX += (mouseX - dotX) * 0.2;
        dotY += (mouseY - dotY) * 0.2;
        outlineX += (mouseX - outlineX) * 0.15;
        outlineY += (mouseY - outlineY) * 0.15;

        dot.style.transform = `translate(${dotX}px, ${dotY}px) translate(-50%, -50%)`;
        outline.style.transform = `translate(${outlineX}px, ${outlineY}px) translate(-50%, -50%)`;

        requestAnimationFrame(animateCursor);
    }
    animateCursor();

    // Cursor Hover States
    const interactiveElements = document.querySelectorAll('a, button, .tilt-card');
    interactiveElements.forEach(el => {
        el.addEventListener('mouseenter', () => {
            outline.style.width = '60px';
            outline.style.height = '60px';
            outline.style.backgroundColor = 'rgba(255, 87, 34, 0.1)';
        });
        el.addEventListener('mouseleave', () => {
            outline.style.width = '40px';
            outline.style.height = '40px';
            outline.style.backgroundColor = 'transparent';
        });
    });

    // ------------------------------------------------
    // PREMIUM FEATURES: PAGE TRANSITIONS
    // ------------------------------------------------
    const loader = document.getElementById('page-loader');
    if (loader) {
        // Initial hide
        setTimeout(() => {
            loader.classList.add('fade-out');
        }, 100);

        // Fix for "White Screen" on back/forward navigation
        window.addEventListener('pageshow', (event) => {
            if (event.persisted) {
                loader.classList.add('fade-out');
            }
        });
    }

    // Intercept link clicks for smooth fade-out
    document.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', (e) => {
            if (e.defaultPrevented) return;
            if (link.hostname === window.location.hostname && !link.hash && link.target !== '_blank') {
                e.preventDefault();
                loader.classList.remove('fade-out');
                setTimeout(() => {
                    window.location.href = link.href;
                }, 150);
            }
        });
    });

    // ------------------------------------------------
    // TORCH EFFECT (3D TILT REMOVED)
    // ------------------------------------------------
    const cards = document.querySelectorAll(".card-shadow"); // Changed from .tilt-card

    cards.forEach(card => {
        // Add torch overlay div if not present
        if (!card.querySelector('.torch-overlay')) {
            const torch = document.createElement('div');
            torch.className = 'torch-overlay';
            card.appendChild(torch);
        }

        card.addEventListener("mousemove", (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            // Torch positioning only
            card.style.setProperty('--x', `${x}px`);
            card.style.setProperty('--y', `${y}px`);
        });
    });

    // ------------------------------------------------
    // PREMIUM FEATURES: MENU PARALLAX
    // ------------------------------------------------
    window.addEventListener('scroll', () => {
        const scrolled = window.scrollY;

        document.querySelectorAll('.parallax-img').forEach(img => {
            const rect = img.getBoundingClientRect();
            // Only calculate if visible on screen
            if (rect.top < window.innerHeight && rect.bottom > 0) {
                const speed = 0.05;
                const yOffset = (window.innerHeight / 2 - rect.top) * speed;
                img.style.transform = `translateY(${yOffset}px) scale(1.1)`;
            }
        });
    });
});
