/**
 * Controller of the PAM_ROTATION_INTERVAL field type: a number of hours,
 * shown only while passwords rotate periodically. For a platform, that is
 * its "rotation-mode"; for a connection ("pam-rotation-interval"), its own
 * "pam-rotation-mode", or its platform's when left to the platform.
 */
angular.module('guacPam').controller('pamRotationIntervalFieldController', ['$scope', '$element', '$injector',
        function pamRotationIntervalFieldController($scope, $element, $injector) {

    var pamService = $injector.get('pamService');

    // As Guacamole's own NUMERIC fields: a number typed, a string stored
    $scope.$watch('model', function modelChanged(model) {
        $scope.typedValue = (model ? Number(model) : null);
    });
    $scope.$watch('typedValue', function typedValueChanged(typedValue) {
        $scope.model = ((typedValue || typedValue === 0) ? typedValue.toString() : '');
    });

    /**
     * Whether this is a connection's interval, whose default is its
     * platform's.
     */
    var ofConnection = $scope.field.name.indexOf('pam-') === 0;

    /**
     * The rotation mode of each platform, by identifier, for connections
     * leaving theirs to the platform.
     */
    var platformModes = {};

    if (ofConnection) {
        pamService.getPlatforms().then(function platformsRetrieved(platforms) {
            platforms.forEach(function addMode(platform) {
                platformModes[String(platform.id)] = platform.policy && platform.policy['rotation-mode'];
            });
        }, angular.noop);
    }

    /**
     * The values of the whole form this field is part of, which Guacamole
     * keeps on the scope of its form directive.
     */
    var formValues = function formValues() {
        for (var scope = $scope; scope; scope = scope.$parent) {
            if (scope.values)
                return scope.values;
        }
        return {};
    };

    var isPeriodic = function isPeriodic() {
        var values = formValues();
        if (!ofConnection)
            return values['rotation-mode'] === 'periodic';
        return (values['pam-rotation-mode'] || platformModes[values['pam-platform']]) === 'periodic';
    };

    // Hides the field's whole row, header included
    $scope.$watch(isPeriodic, function periodicChanged(periodic) {
        var row = $element[0] && $element[0].closest && $element[0].closest('.labeled-field');
        if (row)
            row.classList.toggle('pam-hidden', !periodic);
    });

}]);
