/**
 * Hands a file chosen with a file input to an expression, as "file":
 * pam-file-select="read(file)". The input is cleared afterwards, so the same
 * file can be chosen again.
 */
angular.module('guacPam').directive('pamFileSelect', ['$parse', function pamFileSelect($parse) {

    return {
        restrict : 'A',
        link     : function linkFileSelect(scope, element, attrs) {
            var handle = $parse(attrs.pamFileSelect);
            element.on('change', function fileChosen() {
                var file = element[0].files && element[0].files[0];
                element[0].value = '';
                if (file)
                    scope.$apply(function handleFile() { handle(scope, { file : file }); });
            });
        }
    };

}]);

/**
 * Hands a file dropped on the element to an expression, as "file":
 * pam-file-drop="read(file)". The element has the class "pam-drop-target"
 * while a file is dragged over it.
 */
angular.module('guacPam').directive('pamFileDrop', ['$parse', function pamFileDrop($parse) {

    return {
        restrict : 'A',
        link     : function linkFileDrop(scope, element, attrs) {

            var handle = $parse(attrs.pamFileDrop);

            element.on('dragenter dragover', function fileOver(event) {
                event.preventDefault();
                element.addClass('pam-drop-target');
            });

            element.on('dragleave', function fileLeft(event) {
                if (!element[0].contains(event.relatedTarget))
                    element.removeClass('pam-drop-target');
            });

            element.on('drop', function fileDropped(event) {
                event.preventDefault();
                element.removeClass('pam-drop-target');
                var files = (event.dataTransfer || (event.originalEvent && event.originalEvent.dataTransfer) || {}).files;
                if (files && files[0])
                    scope.$apply(function handleFile() { handle(scope, { file : files[0] }); });
            });

        }
    };

}]);
