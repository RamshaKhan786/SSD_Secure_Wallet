function meter() {
  const v = document.getElementById('pw').value;
  let s = (v.length >= 8) + (v.length >= 12) + /[A-Z]/.test(v) + /\d/.test(v) + /[^A-Za-z0-9]/.test(v);
  const f = document.getElementById('fill');
  f.style.width = s * 20 + '%';
  f.style.background = ['#ef4444', '#ef4444', '#f59e0b', '#f59e0b', '#22c55e', '#22c55e'][s];
  document.getElementById('lbl').textContent = v ? ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'][s] : '';
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('pw').addEventListener('input', meter);
});
