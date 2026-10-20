/**
 * An "i" next to the header of a form field or section, showing its help on
 * hover or focus, for headers whose namespace has a FIELD_HELP_ or
 * SECTION_HELP_ string beside their FIELD_HEADER_ or SECTION_HEADER_ one.
 * Placed by templates/pamFieldHelpPatch.html and
 * templates/pamSectionHelpPatch.html, in Guacamole's own form templates;
 * shows nothing for headers without help.
 */
angular.module('guacPam').directive('pamFieldHelp', [function pamFieldHelp() {

    return {
        restrict    : 'E',
        scope       : {
            namespace : '<',
            field     : '<',
            section   : '<'
        },
        template    : '<span class="pam-field-help" ng-if="help" tabindex="0" role="img" aria-label="{{ help }}">'
                    + '<span class="pam-field-help-text" role="tooltip">{{ help }}</span>'
                    + '</span>',
        controller  : ['$scope', '$injector', function pamFieldHelpController($scope, $injector) {

            var $translate               = $injector.get('$translate');
            var translationStringService = $injector.get('translationStringService');

            $scope.help = null;

            var key = function key() {
                var name = $scope.section || ($scope.field && $scope.field.name);
                if (!$scope.namespace || !name)
                    return null;
                return translationStringService.canonicalize($scope.namespace)
                        + ($scope.section ? '.SECTION_HELP_' : '.FIELD_HELP_')
                        + translationStringService.canonicalize(name);
            };

            $scope.$watch(key, function keyChanged(helpKey) {
                $scope.help = null;
                if (!helpKey)
                    return;
                $translate(helpKey).then(function helpTranslated(text) {
                    if (text !== helpKey && key() === helpKey)
                        $scope.help = text;
                }, angular.noop);
            });

        }]
    };

}]);
