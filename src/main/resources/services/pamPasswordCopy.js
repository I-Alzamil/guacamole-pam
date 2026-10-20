/**
 * Copies a password to the clipboard, falling back to execCommand where the
 * Clipboard API is unavailable (plain HTTP).
 */
angular.module('guacPam').factory('pamPasswordCopy', ['$injector', function pamPasswordCopy($injector) {

    // Required services
    var $document = $injector.get('$document');
    var $q        = $injector.get('$q');
    var $window   = $injector.get('$window');

    /**
     * Resolves once copied, or rejects if the browser refused.
     */
    return function copy(password) {

        if ($window.navigator.clipboard && $window.isSecureContext)
            return $q.when($window.navigator.clipboard.writeText(password));

        var textarea = $document[0].createElement('textarea');
        textarea.value = password;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        $document[0].body.appendChild(textarea);
        textarea.select();
        try {
            return $document[0].execCommand('copy') ? $q.resolve() : $q.reject();
        }
        finally {
            $document[0].body.removeChild(textarea);
        }

    };

}]);
