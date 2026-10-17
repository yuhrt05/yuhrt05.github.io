/* ============================================
   CYBERPUNK CURSOR EFFECT
   - Neon dot: snaps to cursor instantly
   - Glowing ring: follows with a smooth lag
   ============================================ */
(function () {
  const dot  = document.createElement('div');
  const ring = document.createElement('div');

  dot.id  = 'cursor-dot';
  ring.id = 'cursor-ring';

  document.body.appendChild(dot);
  document.body.appendChild(ring);

  let mouseX = -100, mouseY = -100;
  let ringX  = -100, ringY  = -100;

  /* Track cursor position */
  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
    dot.style.transform = `translate(${mouseX}px, ${mouseY}px)`;
  });

  /* Smooth ring animation */
  function animateRing() {
    ringX += (mouseX - ringX) * 0.12;
    ringY += (mouseY - ringY) * 0.12;
    ring.style.transform = `translate(${ringX}px, ${ringY}px)`;
    requestAnimationFrame(animateRing);
  }
  animateRing();

  /* Scale up ring when hovering clickable elements */
  const clickables = 'a, button, label, input, select, textarea, [role="button"], .post-preview, .card';
  document.querySelectorAll(clickables).forEach(el => {
    el.addEventListener('mouseenter', () => ring.classList.add('cursor-hover'));
    el.addEventListener('mouseleave', () => ring.classList.remove('cursor-hover'));
  });

  /* Also handle dynamically added elements */
  document.addEventListener('mouseover', (e) => {
    if (e.target.matches(clickables)) {
      ring.classList.add('cursor-hover');
    }
  });
  document.addEventListener('mouseout', (e) => {
    if (e.target.matches(clickables)) {
      ring.classList.remove('cursor-hover');
    }
  });

  /* Click burst effect */
  document.addEventListener('mousedown', () => ring.classList.add('cursor-click'));
  document.addEventListener('mouseup',   () => ring.classList.remove('cursor-click'));
})();
