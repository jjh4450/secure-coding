// data-confirm 속성이 있는 폼은 제출 전에 확인창을 띄운다.
// CSP가 인라인 이벤트 핸들러(onsubmit=...)를 차단하므로 외부 스크립트로 처리한다.
document.addEventListener('submit', function (e) {
  var form = e.target;
  if (form && form.getAttribute && form.getAttribute('data-confirm')) {
    if (!window.confirm(form.getAttribute('data-confirm'))) {
      e.preventDefault();
    }
  }
}, true);
