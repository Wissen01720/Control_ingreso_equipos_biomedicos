/**
 * Sistema de Captchas Personalizados PDS-006
 * Implementa diferentes tipos de captchas para operaciones críticas
 */

// ==================== CAPTCHA MATEMÁTICO ====================
class MathCaptcha {
  constructor() {
    this.num1 = Math.floor(Math.random() * 20) + 1;
    this.num2 = Math.floor(Math.random() * 20) + 1;
    this.operators = ["+", "-", "*"];
    this.operator =
      this.operators[Math.floor(Math.random() * this.operators.length)];
  }

  getQuestion() {
    return `¿Cuánto es ${this.num1} ${this.operator} ${this.num2}?`;
  }

  getAnswer() {
    switch (this.operator) {
      case "+":
        return this.num1 + this.num2;
      case "-":
        return this.num1 - this.num2;
      case "*":
        return this.num1 * this.num2;
      default:
        return 0;
    }
  }

  verify(userAnswer) {
    return parseInt(userAnswer) === this.getAnswer();
  }
}

// ==================== CAPTCHA DE COLORES ====================
class ColorCaptcha {
  constructor() {
    this.colors = [
      { name: "rojo", hex: "#dc3545", variants: ["rojo", "red"] },
      { name: "azul", hex: "#0d6efd", variants: ["azul", "blue"] },
      { name: "verde", hex: "#198754", variants: ["verde", "green"] },
      { name: "amarillo", hex: "#ffc107", variants: ["amarillo", "yellow"] },
      {
        name: "morado",
        hex: "#6f42c1",
        variants: ["morado", "purple", "violeta"],
      },
      { name: "naranja", hex: "#fd7e14", variants: ["naranja", "orange"] },
    ];
    this.selectedColor =
      this.colors[Math.floor(Math.random() * this.colors.length)];
  }

  getHTML() {
    return `
            <div class="text-center mb-3">
                <p class="mb-2">¿De qué color es este cuadro?</p>
                <div style="width: 100px; height: 100px; background: ${this.selectedColor.hex}; 
                            margin: 0 auto; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                            animation: pulse 2s ease-in-out infinite;">
                </div>
            </div>
        `;
  }

  verify(userAnswer) {
    const normalized = userAnswer.toLowerCase().trim();
    return this.selectedColor.variants.some(
      (variant) => variant === normalized
    );
  }
}

// ==================== CAPTCHA DE SECUENCIA ====================
class SequenceCaptcha {
  constructor() {
    this.start = Math.floor(Math.random() * 10) + 1;
    this.step = Math.floor(Math.random() * 3) + 2;
    this.sequence = [
      this.start,
      this.start + this.step,
      this.start + 2 * this.step,
    ];
    this.answer = this.start + 3 * this.step;
  }

  getQuestion() {
    return `Completa la secuencia: ${this.sequence.join(", ")}, ____`;
  }

  verify(userAnswer) {
    return parseInt(userAnswer) === this.answer;
  }
}

// ==================== CAPTCHA DE PALABRAS ====================
class WordCaptcha {
  constructor() {
    this.words = [
      { word: "SEGURIDAD", hint: "Protección contra amenazas" },
      { word: "HOSPITAL", hint: "Institución de salud" },
      { word: "EQUIPO", hint: "Dispositivo o aparato" },
      { word: "BIOMEDICO", hint: "Relacionado con medicina y tecnología" },
      { word: "CONTROL", hint: "Supervisión o regulación" },
    ];
    this.selected = this.words[Math.floor(Math.random() * this.words.length)];
    this.shuffled = this.shuffleWord(this.selected.word);
  }

  shuffleWord(word) {
    const arr = word.split("");
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join("");
  }

  getQuestion() {
    return `Ordena estas letras: <strong>${this.shuffled}</strong><br>
                <small class="text-muted">Pista: ${this.selected.hint}</small>`;
  }

  verify(userAnswer) {
    return userAnswer.toUpperCase().trim() === this.selected.word;
  }
}

// ==================== CAPTCHA DE SLIDER ====================
class SliderCaptcha {
  constructor() {
    this.targetValue = Math.floor(Math.random() * 41) + 30; // 30-70
  }

  getHTML() {
    return `
            <div class="mb-3">
                <label class="form-label">Desliza hasta el valor: <strong>${this.targetValue}</strong></label>
                <input type="range" class="form-range" id="sliderCaptchaInput" 
                       min="0" max="100" value="50" step="1">
                <div class="text-center mt-2">
                    Valor actual: <strong id="sliderValue">50</strong>
                </div>
            </div>
        `;
  }

  verify(userAnswer) {
    return Math.abs(parseInt(userAnswer) - this.targetValue) <= 2; // Margen de error de ±2
  }
}

// ==================== CAPTCHA MANAGER ====================
class CaptchaManager {
  constructor() {
    this.currentCaptcha = null;
    this.types = ["math", "color", "sequence", "word", "slider"];
  }

  generate(type = null) {
    if (!type) {
      type = this.types[Math.floor(Math.random() * this.types.length)];
    }

    switch (type) {
      case "math":
        this.currentCaptcha = new MathCaptcha();
        break;
      case "color":
        this.currentCaptcha = new ColorCaptcha();
        break;
      case "sequence":
        this.currentCaptcha = new SequenceCaptcha();
        break;
      case "word":
        this.currentCaptcha = new WordCaptcha();
        break;
      case "slider":
        this.currentCaptcha = new SliderCaptcha();
        break;
    }

    this.captchaType = type;
    return this;
  }

  render(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    let html = "";

    if (this.captchaType === "color" || this.captchaType === "slider") {
      html = this.currentCaptcha.getHTML();
    } else {
      const question = this.currentCaptcha.getQuestion();
      html = `
                <div class="mb-3">
                    <label class="form-label">${question}</label>
                    <input type="text" class="form-control" id="captchaAnswer" 
                           placeholder="Escribe tu respuesta" required autocomplete="off">
                </div>
            `;
    }

    container.innerHTML = html;

    // Si es slider, agregar event listener
    if (this.captchaType === "slider") {
      const slider = document.getElementById("sliderCaptchaInput");
      const valueDisplay = document.getElementById("sliderValue");
      if (slider && valueDisplay) {
        slider.addEventListener("input", (e) => {
          valueDisplay.textContent = e.target.value;
        });
      }
    }
  }

  verify() {
    let userAnswer;

    if (this.captchaType === "slider") {
      const slider = document.getElementById("sliderCaptchaInput");
      userAnswer = slider ? slider.value : null;
    } else if (this.captchaType === "color") {
      const input = document.getElementById("captchaAnswer");
      userAnswer = input ? input.value : null;
    } else {
      const input = document.getElementById("captchaAnswer");
      userAnswer = input ? input.value : null;
    }

    if (!userAnswer) return false;

    const isValid = this.currentCaptcha.verify(userAnswer);
    return isValid;
  }
}

// ==================== FUNCIONES GLOBALES ====================
let captchaManager = null;

function initializeCaptcha(containerId, type = null) {
  captchaManager = new CaptchaManager();
  captchaManager.generate(type);
  captchaManager.render(containerId);
}

function verifyCaptcha() {
  if (!captchaManager) {
    console.error("Captcha no inicializado");
    return false;
  }
  return captchaManager.verify();
}

function refreshCaptcha(containerId) {
  if (captchaManager) {
    captchaManager.generate();
    captchaManager.render(containerId);
  }
}

// Exportar para uso global
window.initializeCaptcha = initializeCaptcha;
window.verifyCaptcha = verifyCaptcha;
window.refreshCaptcha = refreshCaptcha;
window.CaptchaManager = CaptchaManager;
