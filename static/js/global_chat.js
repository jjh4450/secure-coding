// 전체 실시간 채팅 클라이언트.
// XSS 방지를 위해 서버가 보낸 문자열은 textContent로만 렌더링한다(innerHTML 금지).
(function () {
  var socket = io();
  var messages = document.getElementById('messages');
  var input = document.getElementById('chat_input');
  var form = document.getElementById('chat_form');

  function appendMessage(username, message) {
    var item = document.createElement('div');
    item.className = 'msg';
    var who = document.createElement('span');
    who.className = 'who';
    who.textContent = username + ':';
    var body = document.createElement('span');
    body.textContent = ' ' + message;
    item.appendChild(who);
    item.appendChild(body);
    messages.appendChild(item);
    messages.scrollTop = messages.scrollHeight;
  }

  socket.on('message', function (data) {
    appendMessage(data.username, data.message);
  });

  socket.on('chat_error', function (data) {
    appendMessage('[알림]', data.message);
  });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var message = input.value.trim();
    if (message) {
      // username은 서버 세션에서 결정하므로 전송하지 않는다
      socket.emit('send_message', { message: message });
      input.value = '';
    }
  });
})();
