const q = s => document.querySelector(s);

function fill(u, p) {
  q('[name=username]').value = u;
  q('[name=password]').value = p;
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-fill-user]').forEach(btn => {
    btn.addEventListener('click', () => fill(btn.dataset.fillUser, btn.dataset.fillPass));
  });

  const sqliBtn = q('#fillSqli');
  if (sqliBtn) sqliBtn.addEventListener('click', () => fill("ali' --", 'anything'));

  const showPw = q('#showpw');
  if (showPw) {
    showPw.addEventListener('click', () => {
      const i = q('[name=password]');
      i.type = i.type === 'password' ? 'text' : 'password';
    });
  }
});
