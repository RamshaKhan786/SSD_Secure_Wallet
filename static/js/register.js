function meter() {
  const value = document.getElementById('pw').value;
  let score =
    Number(value.length >= 8) +
    Number(value.length >= 12) +
    Number(/[A-Z]/.test(value)) +
    Number(/\d/.test(value)) +
    Number(/[^A-Za-z0-9]/.test(value));

  const fill = document.getElementById('fill');
  fill.className = `meter-fill score-${score}`;

  const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];
  document.getElementById('lbl').textContent = value ? labels[score] : '';
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('pw').addEventListener('input', meter);
});
