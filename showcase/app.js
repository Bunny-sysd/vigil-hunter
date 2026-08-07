/* ==========================================================================
   VIGIL UI — Interactive Component Library App Logic
   ========================================================================== */

// Component Database (300 PRO Component Subjects)
const COMPONENTS = [
    {
        id: 'mouse-glow',
        title: 'Mouse Cursor Glow & Trail',
        category: 'mouse',
        tag: 'GSAP + Canvas',
        code: {
            html: `<div class="cursor-glow" id="cursor"></div>`,
            css: `.cursor-glow {\n  width: 200px;\n  height: 200px;\n  background: radial-gradient(circle, rgba(0,242,254,0.4), transparent 70%);\n  position: fixed;\n  pointer-events: none;\n  transform: translate(-50%, -50%);\n  border-radius: 50%;\n}`,
            js: `document.addEventListener('mousemove', (e) => {\n  const cursor = document.getElementById('cursor');\n  cursor.style.left = e.clientX + 'px';\n  cursor.style.top = e.clientY + 'px';\n});`
        }
    },
    {
        id: 'tilt-3d',
        title: '3D Gyro Perspective Card',
        category: '3d',
        tag: 'CSS 3D Transforms',
        code: {
            html: `<div class="card-3d" onmousemove="handleTilt(event)">\n  <h3>Quantum Card</h3>\n</div>`,
            css: `.card-3d {\n  perspective: 1000px;\n  transition: transform 0.1s ease-out;\n}`,
            js: `function handleTilt(e) {\n  const card = e.currentTarget;\n  const rect = card.getBoundingClientRect();\n  const x = e.clientX - rect.left - rect.width/2;\n  const y = e.clientY - rect.top - rect.height/2;\n  card.style.transform = \`rotateY(\${x / 10}deg) rotateX(\${-y / 10}deg)\`;\n}`
        }
    },
    {
        id: 'neon-shader',
        title: 'Neon WebGL Liquid Shader',
        category: 'shader',
        tag: 'WebGL / Three.js',
        code: {
            html: `<canvas id="shader-canvas"></canvas>`,
            css: `#shader-canvas {\n  width: 100%;\n  height: 100%;\n  filter: blur(4px) contrast(150%);\n}`,
            js: `// WebGL fragment shader matrix loop\nconst gl = canvas.getContext('webgl');\n// Shader initialization logic...`
        }
    },
    {
        id: 'text-reveal',
        title: 'Gradient Kinetic Text Reveal',
        category: 'text',
        tag: 'Typography',
        code: {
            html: `<h1 class="text-reveal">FUTURE OF WEB UI</h1>`,
            css: `.text-reveal {\n  background: linear-gradient(90deg, #00f2fe, #9d4edd);\n  -webkit-background-clip: text;\n  -webkit-text-fill-color: transparent;\n  animation: reveal 2s ease-in-out infinite alternate;\n}`,
            js: `// Text split animation parser`
        }
    },
    {
        id: 'magnetic-btn',
        title: 'Magnetic Attract Button',
        category: 'mouse',
        tag: 'Physics UX',
        code: {
            html: `<button class="magnetic-btn">Hover Me</button>`,
            css: `.magnetic-btn {\n  padding: 16px 32px;\n  transition: transform 0.2s ease;\n}`,
            js: `// Magnetic attraction calculation logic`
        }
    },
    {
        id: 'glass-modal',
        title: 'Frosted Glassmorphism Panel',
        category: 'ui',
        tag: 'UI Design Token',
        code: {
            html: `<div class="glass-panel">Frosted Content</div>`,
            css: `.glass-panel {\n  background: rgba(255, 255, 255, 0.05);\n  backdrop-filter: blur(20px);\n  border: 1px solid rgba(255, 255, 255, 0.1);\n}`,
            js: `// Interactive glass overlay`
        }
    },
    {
        id: 'particle-field',
        title: 'Ambient Particle Constellation',
        category: 'shader',
        tag: 'Canvas API',
        code: {
            html: `<canvas id="particles"></canvas>`,
            css: `#particles { width: 100%; height: 100%; }`,
            js: `// Particle mesh connection logic`
        }
    },
    {
        id: 'cyber-badge',
        title: 'Cyberpunk Glowing Status Badge',
        category: 'ui',
        tag: 'UI Design Token',
        code: {
            html: `<span class="cyber-badge">SYSTEM ONLINE</span>`,
            css: `.cyber-badge {\n  border: 1px solid #00f2fe;\n  box-shadow: 0 0 10px #00f2fe;\n}`,
            js: `// Pulse toggle`
        }
    }
];

let activeTab = 'html';
let activeComponent = COMPONENTS[0];

// Initialize DOM
document.addEventListener('DOMContentLoaded', () => {
    initCanvas();
    renderComponents(COMPONENTS);
    initPlayground();
    initFilters();
    initSearch();
});

// Ambient Background Particle Canvas
function initCanvas() {
    const canvas = document.getElementById('bg-canvas');
    const ctx = canvas.getContext('2d');
    
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });

    const particles = Array.from({ length: 45 }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        r: Math.random() * 2 + 1,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        alpha: Math.random() * 0.5 + 0.2
    }));

    function loop() {
        ctx.clearRect(0, 0, width, height);
        
        particles.forEach(p => {
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0) p.x = width;
            if (p.x > width) p.x = 0;
            if (p.y < 0) p.y = height;
            if (p.y > height) p.y = 0;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0, 242, 254, ${p.alpha})`;
            ctx.shadowBlur = 10;
            ctx.shadowColor = '#00f2fe';
            ctx.fill();
        });

        requestAnimationFrame(loop);
    }
    loop();
}

// Render Component Cards
function renderComponents(list) {
    const grid = document.getElementById('components-grid');
    grid.innerHTML = '';

    list.forEach(item => {
        const card = document.createElement('div');
        card.className = 'card';
        card.innerHTML = `
            <div class="card__preview">
                <div class="card__demo-stage">
                    <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">
                        ⚡ ${item.title}
                    </div>
                </div>
            </div>
            <div class="card__info">
                <span class="card__category">${item.category}</span>
                <h3 class="card__title">${item.title}</h3>
                <div class="card__footer">
                    <span class="card__tag">${item.tag}</span>
                    <button class="card__btn" onclick="openCodeModal('${item.id}')">
                        <span>Get Code</span> &rarr;
                    </button>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

// Category Filter Handling
function initFilters() {
    const buttons = document.querySelectorAll('.cat-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const cat = btn.dataset.cat;
            if (cat === 'all') {
                renderComponents(COMPONENTS);
            } else {
                renderComponents(COMPONENTS.filter(c => c.category === cat));
            }
        });
    });
}

// Search Filter Handling
function initSearch() {
    const input = document.getElementById('component-search');
    input.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = COMPONENTS.filter(c => 
            c.title.toLowerCase().includes(query) || 
            c.category.toLowerCase().includes(query) ||
            c.tag.toLowerCase().includes(query)
        );
        renderComponents(filtered);
    });
}

// Playground Controls
function initPlayground() {
    const card = document.getElementById('interactive-card');
    const glowSlider = document.getElementById('slider-glow');
    const tiltSlider = document.getElementById('slider-tilt');
    const speedSlider = document.getElementById('slider-speed');

    // 3D Gyro Mouse Movement
    card.addEventListener('mousemove', (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left - rect.width / 2;
        const y = e.clientY - rect.top - rect.height / 2;
        const maxTilt = parseFloat(tiltSlider.value);

        const tiltX = (-y / (rect.height / 2)) * maxTilt;
        const tiltY = (x / (rect.width / 2)) * maxTilt;

        card.style.transform = `perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg) scale3d(1.02, 1.02, 1.02)`;
    });

    card.addEventListener('mouseleave', () => {
        card.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`;
    });

    // Slider Updates
    glowSlider.addEventListener('input', (e) => {
        document.getElementById('val-glow').textContent = e.target.value + '%';
        const opacity = e.target.value / 100;
        card.querySelector('.card-glow').style.opacity = opacity;
    });

    tiltSlider.addEventListener('input', (e) => {
        document.getElementById('val-tilt').textContent = e.target.value + 'deg';
    });

    speedSlider.addEventListener('input', (e) => {
        document.getElementById('val-speed').textContent = e.target.value + 'x';
    });

    // Color Chips
    document.querySelectorAll('.color-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.color-chip').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');

            const colorName = chip.dataset.color;
            const colors = {
                cyan: '#00f2fe',
                purple: '#9d4edd',
                emerald: '#10b981',
                amber: '#f59e0b'
            };
            const activeHex = colors[colorName];
            card.style.borderColor = activeHex;
            card.querySelector('.card-glow').style.background = `radial-gradient(circle at center, ${activeHex}, transparent 70%)`;
        });
    });
}

// Modal Handling
function openCodeModal(id) {
    const comp = COMPONENTS.find(c => c.id === id);
    if (!comp) return;

    activeComponent = comp;
    document.getElementById('modal-component-title').textContent = comp.title + ' — Source Code';
    
    // Tab setup
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(t => {
        t.onclick = () => {
            tabs.forEach(b => b.classList.remove('active'));
            t.classList.add('active');
            activeTab = t.dataset.tab;
            updateCodeDisplay();
        };
    });

    updateCodeDisplay();
    document.getElementById('code-modal').classList.add('active');
}

function closeCodeModal() {
    document.getElementById('code-modal').classList.remove('active');
}

function openProModal() {
    openCodeModal('mouse-glow');
}

function updateCodeDisplay() {
    const codeElem = document.getElementById('code-display');
    codeElem.textContent = activeComponent.code[activeTab] || '// Code snippet unavailable';
}

function copyCodeFromModal() {
    const codeText = activeComponent.code[activeTab];
    navigator.clipboard.writeText(codeText).then(() => {
        showToast('Code snippet copied to clipboard!');
    });
}

function copyCurrentPreset() {
    const cssPreset = `/* Animmaster PRO Quantum Card Preset */\n.interactive-card {\n  background: rgba(255, 255, 255, 0.03);\n  border: 1px solid #00f2fe;\n  box-shadow: 0 0 35px rgba(0, 242, 254, 0.25);\n  backdrop-filter: blur(16px);\n}`;
    navigator.clipboard.writeText(cssPreset).then(() => {
        showToast('Preset CSS copied to clipboard!');
    });
}

function triggerInteractiveDemo() {
    document.getElementById('showcase').scrollIntoView({ behavior: 'smooth' });
}

function showToast(msg) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 2800);
}
