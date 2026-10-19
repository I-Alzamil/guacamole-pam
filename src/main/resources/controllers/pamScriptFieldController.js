/**
 * Controller of the PAM_SCRIPT field type: validates the sequence script
 * shortly after typing stops, for the status line above the editor.
 */
angular.module('guacPam').controller('pamScriptFieldController', ['$scope', '$injector',
        function pamScriptFieldController($scope, $injector) {

    var $timeout   = $injector.get('$timeout');
    var $translate = $injector.get('$translate');
    var pamService = $injector.get('pamService');

    /**
     * Latest validation result of the script, or null.
     */
    $scope.validation = null;

    var pending = null;

    $scope.$watch('model', function scriptChanged(script) {
        $timeout.cancel(pending);
        pending = $timeout(function validateScript() {
            pamService.validate(script || '').then(function validated(result) {
                if ($scope.model === script)
                    $scope.validation = result;
            });
        }, 300);
    });

    /**
     * All validation errors as text, one per line, for the tooltip of the
     * status line.
     */
    $scope.describeErrors = function describeErrors() {
        var errors = ($scope.validation && $scope.validation.errors) || [];
        return errors.map(function describeError(error) {
            return (error.line ? $translate.instant('PAM.TEXT_LINE', { LINE : error.line }) + ' ' : '')
                 + error.message;
        }).join('\n');
    };

    $scope.$on('$destroy', function scriptFieldDestroyed() {
        $timeout.cancel(pending);
    });

}]);
