/**
 * ============================================
 * ANIMACIONES CON ANIME.JS - PDS-006
 * ============================================
 */

// Esperar a que el DOM esté listo
document.addEventListener("DOMContentLoaded", function () {
  // ========================================
  // ANIMACIÓN DE PÁGINA DE LOGIN
  // ========================================
  if (document.querySelector(".login-card")) {
    // Animar la tarjeta de login
    anime({
      targets: ".login-card",
      translateY: [-50, 0],
      opacity: [0, 1],
      duration: 800,
      easing: "easeOutExpo",
    });

    // Animar el icono con efecto flotante
    anime({
      targets: ".login-card .icon",
      translateY: [-20, 0],
      scale: [0.8, 1],
      opacity: [0, 1],
      duration: 1000,
      easing: "easeOutElastic(1, .8)",
      delay: 200,
    });

    // Efecto flotante continuo para el icono
    anime({
      targets: ".login-card .icon",
      translateY: [-5, 5],
      duration: 2000,
      loop: true,
      direction: "alternate",
      easing: "easeInOutSine",
    });

    // Animar los campos del formulario en secuencia
    anime({
      targets: ".login-card .mb-3, .login-card .mb-4, .login-card .d-grid",
      translateX: [-30, 0],
      opacity: [0, 1],
      duration: 600,
      delay: anime.stagger(100, { start: 400 }),
      easing: "easeOutCubic",
    });
  }

  // ========================================
  // ANIMACIÓN DE CARDS EN EL DASHBOARD
  // ========================================
  if (document.querySelectorAll(".card").length > 0) {
    anime({
      targets: ".card",
      translateY: [30, 0],
      opacity: [0, 1],
      duration: 600,
      delay: anime.stagger(80),
      easing: "easeOutCubic",
    });
  }

  // ========================================
  // ANIMACIÓN DE TABLAS
  // ========================================
  if (document.querySelector("table tbody tr")) {
    anime({
      targets: "table tbody tr",
      translateX: [-20, 0],
      opacity: [0, 1],
      duration: 500,
      delay: anime.stagger(50, { start: 200 }),
      easing: "easeOutCubic",
    });
  }

  // ========================================
  // ANIMACIÓN DE BOTONES AL HOVER
  // ========================================
  const buttons = document.querySelectorAll(".btn");
  buttons.forEach((btn) => {
    btn.addEventListener("mouseenter", function () {
      anime({
        targets: this,
        scale: 1.05,
        duration: 300,
        easing: "easeOutCubic",
      });
    });

    btn.addEventListener("mouseleave", function () {
      anime({
        targets: this,
        scale: 1,
        duration: 300,
        easing: "easeOutCubic",
      });
    });
  });

  // ========================================
  // ANIMACIÓN DE BADGES Y ALERTS
  // ========================================
  if (document.querySelectorAll(".badge, .alert").length > 0) {
    anime({
      targets: ".badge, .alert",
      scale: [0.8, 1],
      opacity: [0, 1],
      duration: 400,
      delay: anime.stagger(100),
      easing: "easeOutBack",
    });
  }

  // ========================================
  // ANIMACIÓN DEL NAVBAR
  // ========================================
  if (document.querySelector(".navbar")) {
    anime({
      targets: ".navbar",
      translateY: [-100, 0],
      opacity: [0, 1],
      duration: 600,
      easing: "easeOutExpo",
    });

    // Animar items del menú
    anime({
      targets: ".navbar-nav .nav-item",
      translateY: [-20, 0],
      opacity: [0, 1],
      duration: 500,
      delay: anime.stagger(50, { start: 300 }),
      easing: "easeOutCubic",
    });
  }

  // ========================================
  // ANIMACIÓN DEL HEADER
  // ========================================
  if (document.querySelector("header")) {
    anime({
      targets: "header",
      translateY: [-50, 0],
      opacity: [0, 1],
      duration: 700,
      easing: "easeOutExpo",
    });

    // Animar logo
    anime({
      targets: ".usta-logo",
      scale: [0.5, 1],
      rotate: [-10, 0],
      opacity: [0, 1],
      duration: 800,
      easing: "easeOutElastic(1, .6)",
      delay: 200,
    });
  }

  // ========================================
  // ANIMACIÓN DEL FOOTER
  // ========================================
  if (document.querySelector("footer")) {
    anime({
      targets: "footer .row > div",
      translateY: [30, 0],
      opacity: [0, 1],
      duration: 600,
      delay: anime.stagger(200),
      easing: "easeOutCubic",
    });
  }

  // ========================================
  // ANIMACIÓN DE MODALES
  // ========================================
  const modals = document.querySelectorAll(".modal");
  modals.forEach((modal) => {
    modal.addEventListener("shown.bs.modal", function () {
      anime({
        targets: this.querySelector(".modal-content"),
        scale: [0.7, 1],
        opacity: [0, 1],
        duration: 400,
        easing: "easeOutBack",
      });
    });
  });

  // ========================================
  // ANIMACIÓN DE TOASTS/NOTIFICACIONES
  // ========================================
  const toastElList = document.querySelectorAll(".toast");
  toastElList.forEach((toastEl) => {
    toastEl.addEventListener("shown.bs.toast", function () {
      anime({
        targets: this,
        translateX: [100, 0],
        opacity: [0, 1],
        duration: 400,
        easing: "easeOutCubic",
      });
    });
  });

  // ========================================
  // EFECTO DE PARTÍCULAS EN EL FONDO (OPCIONAL)
  // ========================================
  function createFloatingParticles() {
    const particlesContainer = document.createElement("div");
    particlesContainer.className = "particles-container";
    particlesContainer.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: -1;
      opacity: 0.3;
    `;

    for (let i = 0; i < 20; i++) {
      const particle = document.createElement("div");
      particle.className = "particle";
      particle.style.cssText = `
        position: absolute;
        width: ${Math.random() * 5 + 2}px;
        height: ${Math.random() * 5 + 2}px;
        background: linear-gradient(135deg, #667eea, #764ba2);
        border-radius: 50%;
        left: ${Math.random() * 100}%;
        top: ${Math.random() * 100}%;
      `;
      particlesContainer.appendChild(particle);

      anime({
        targets: particle,
        translateY: [
          {
            value: Math.random() * 100 - 50,
            duration: Math.random() * 3000 + 2000,
          },
        ],
        translateX: [
          {
            value: Math.random() * 100 - 50,
            duration: Math.random() * 3000 + 2000,
          },
        ],
        opacity: [
          {
            value: Math.random() * 0.5 + 0.2,
            duration: Math.random() * 2000 + 1000,
          },
        ],
        scale: [
          {
            value: Math.random() * 1.5 + 0.5,
            duration: Math.random() * 2000 + 1000,
          },
        ],
        loop: true,
        direction: "alternate",
        easing: "easeInOutSine",
      });
    }

    // Solo agregar partículas en la página de login
    if (document.querySelector(".login-card")) {
      document.body.appendChild(particlesContainer);
    }
  }

  // Llamar a la función de partículas
  createFloatingParticles();

  // ========================================
  // ANIMACIÓN DE NÚMEROS (CONTADORES)
  // ========================================
  const counters = document.querySelectorAll("[data-counter]");
  counters.forEach((counter) => {
    const target = parseInt(counter.getAttribute("data-counter"));
    const obj = { count: 0 };

    anime({
      targets: obj,
      count: target,
      duration: 2000,
      easing: "easeOutExpo",
      round: 1,
      update: function () {
        counter.textContent = obj.count;
      },
    });
  });

  // ========================================
  // ANIMACIÓN AL HACER SCROLL
  // ========================================
  const observerOptions = {
    threshold: 0.1,
    rootMargin: "0px 0px -50px 0px",
  };

  const observer = new IntersectionObserver(function (entries) {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        anime({
          targets: entry.target,
          translateY: [30, 0],
          opacity: [0, 1],
          duration: 600,
          easing: "easeOutCubic",
        });
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);

  // Observar elementos con la clase .animate-on-scroll
  document.querySelectorAll(".animate-on-scroll").forEach((el) => {
    observer.observe(el);
  });

  // ========================================
  // EFECTO RIPPLE EN BOTONES
  // ========================================
  document.querySelectorAll(".btn").forEach((button) => {
    button.addEventListener("click", function (e) {
      const ripple = document.createElement("span");
      const rect = this.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height);
      const x = e.clientX - rect.left - size / 2;
      const y = e.clientY - rect.top - size / 2;

      ripple.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.6);
        left: ${x}px;
        top: ${y}px;
        pointer-events: none;
      `;

      this.style.position = "relative";
      this.style.overflow = "hidden";
      this.appendChild(ripple);

      anime({
        targets: ripple,
        scale: [0, 4],
        opacity: [1, 0],
        duration: 600,
        easing: "easeOutExpo",
        complete: function () {
          ripple.remove();
        },
      });
    });
  });
});
