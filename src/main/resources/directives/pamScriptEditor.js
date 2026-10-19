/**
 * Plain-text editor for sequence scripts, with line numbers and highlighting
 * of the lines that have errors.
 *
 * The textarea is sized to its content and never scrolls itself; it shares
 * one scrolling container with the line numbers, so the two cannot drift
 * apart.
 */
angular.module('guacPam').directive('pamScriptEditor', [function pamScriptEditor() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {
            script : '=',
            errors : '='
        },
        templateUrl : 'app/ext/pam/templates/pamScriptEditor.html',
        link        : function linkScriptEditor($scope, $element) {

            var textarea = $element.find('textarea')[0];
            var scroller = $element[0].querySelector('.pam-script-scroll');
            var gutter   = $element[0].querySelector('.pam-script-gutter');

            /**
             * 1-based line numbers of the script.
             */
            $scope.lines = [];

            /**
             * Grows or shrinks the textarea to fit its content, but never
             * below the size of the editor.
             */
            var fitToContent = function fitToContent() {

                // Collapsing the textarea to measure it would otherwise make
                // the container jump back to the top
                var top = scroller.scrollTop;
                var left = scroller.scrollLeft;

                // Fill at least the visible area, so clicking anywhere in
                // the editor focuses the textarea
                textarea.style.height = '0';
                textarea.style.width = '0';
                textarea.style.height = Math.max(textarea.scrollHeight, scroller.clientHeight) + 'px';
                textarea.style.width = Math.max(textarea.scrollWidth,
                        scroller.clientWidth - gutter.offsetWidth) + 'px';
                textarea.scrollTop = 0;
                textarea.scrollLeft = 0;

                scroller.scrollTop = top;
                scroller.scrollLeft = left;

            };

            $scope.$watch('script', function scriptChanged(script) {
                var count = (script || '').split('\n').length;
                $scope.lines = [];
                for (var i = 1; i <= count; i++)
                    $scope.lines.push(i);

                // Also covers scripts loaded from the server
                $scope.$$postDigest(fitToContent);
            });

            textarea.addEventListener('input', fitToContent);
            window.addEventListener('resize', fitToContent);
            $scope.$on('$destroy', function editorDestroyed() {
                window.removeEventListener('resize', fitToContent);
            });

            /**
             * Messages of the errors on the given line, or an empty string.
             */
            $scope.errorText = function errorText(line) {
                var messages = [];
                angular.forEach($scope.errors || [], function addMessage(error) {
                    if (error.line === line)
                        messages.push(error.message);
                });
                return messages.join('\n');
            };

            $scope.hasError = function hasError(line) {
                return !!$scope.errorText(line);
            };

            // Indent with Tab instead of leaving the editor
            textarea.addEventListener('keydown', function insertTab(e) {
                if (e.key !== 'Tab' || e.shiftKey)
                    return;
                e.preventDefault();
                var start = textarea.selectionStart;
                var end = textarea.selectionEnd;
                var value = textarea.value;
                textarea.value = value.substring(0, start) + '    ' + value.substring(end);
                textarea.selectionStart = textarea.selectionEnd = start + 4;
                $scope.$apply(function updateScript() {
                    $scope.script = textarea.value;
                });
                fitToContent();
            });

        }
    };

}]);
