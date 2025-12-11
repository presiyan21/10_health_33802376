// js/comments.js

// HTML escaping for user submitted text
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}


// Comment form for a given post
function initComments(postId) {
  const form = document.getElementById('commentForm');
  if (!form) return; 

  const commentList = document.getElementById('commentList');
  const msgEl = document.getElementById('commentMsg');

  // Intercept submit and send via fetch
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(form);

    try {
      const base = (window.BASE || '').replace(/\/$/, ''); 
      const res = await fetch(`${base}/posts/${postId}/comment`, {
        method: 'POST',
        body: formData, 
        headers: { Accept: 'application/json' }
      });

      // Try to parse JSON
      let data;
      try {
        data = await res.json();
      } catch (_) {
        data = null;
      }

      // Show server-side validation / failure
      if (!res.ok || !data?.success) {
        const errMsg = data?.error || 'Failed to post comment';
        if (msgEl) {
          msgEl.textContent = errMsg;
          msgEl.style.color = 'red';
        }
        return;
      }

      // New comment entry
      const c = data.comment;
      const created = c.created_at ? new Date(c.created_at).toLocaleString() : '';

      const li = document.createElement('li');
      li.id = `comment-${c.id}`;

      const name = document.createElement('strong');
      name.textContent = c.username;
      li.appendChild(name);

      const time = document.createElement('small');
      time.style.marginLeft = '8px';
      time.textContent = created;
      li.appendChild(time);

      const p = document.createElement('p');
      p.textContent = c.comment || c.content || '';
      li.appendChild(p);

      // Append to the list and reset form
      commentList?.appendChild(li);

      form.reset();
      if (msgEl) {
        msgEl.textContent = 'Comment posted.';
        msgEl.style.color = 'green';
      }
    } catch (err) {
      console.error('Comment post failed:', err);
      if (msgEl) {
        msgEl.textContent = 'Error posting comment';
        msgEl.style.color = 'red';
      }
    }
  });
}

window.initComments = initComments;
