// 1:1 채팅 클라이언트. 서버 문자열은 textContent로만 렌더링(XSS 방지).
(function () {
  var root = document.getElementById('dm-root');
  if (!root) return;
  var peerId = root.getAttribute('data-peer-id');
  var socket = io();
  var messages = document.getElementById('dm-messages');
  var input = document.getElementById('dm_input');
  var form = document.getElementById('dm_form');

  function appendMessage(sender, message) {
    var item = document.createElement('div');
    item.className = 'msg';
    var who = document.createElement('span');
    who.className = 'who';
    who.textContent = sender + ':';
    var body = document.createElement('span');
    body.textContent = ' ' + message;
    item.appendChild(who);
    item.appendChild(body);
    messages.appendChild(item);
    messages.scrollTop = messages.scrollHeight;
  }

  socket.on('connect', function () {
    socket.emit('join_dm', { peer_id: peerId });
  });

  socket.on('dm', function (data) {
    appendMessage(data.sender_name, data.message);
  });

  socket.on('chat_error', function (data) {
    appendMessage('[알림]', data.message);
  });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var message = input.value.trim();
    if (message) {
      socket.emit('send_dm', { peer_id: peerId, message: message });
      input.value = '';
    }
  });
})();
