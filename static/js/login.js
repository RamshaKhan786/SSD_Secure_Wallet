const q = s => document.querySelector(s);

function fill(username, password) {
  q('[name=username]').value = username;
  q('[name=password]').value = password;
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-fill-user]').forEach(btn => {
    btn.addEventListener('click', () => fill(btn.dataset.fillUser, btn.dataset.fillPass));
  });

  const sqliBtn = q('#fillSqli');
  if (sqliBtn) {
    sqliBtn.addEventListener('click', () => fill("ali' --", 'anything'));
  }

  const showPw = q('#showpw');
  if (showPw) {
    showPw.addEventListener('change', () => {
      const input = q('[name=password]');
      input.type = showPw.checked ? 'text' : 'password';
    });
  }
});
