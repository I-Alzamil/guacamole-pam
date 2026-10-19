/**
 * Controller of the PAM_PLATFORM field type. The model is the platform
 * identifier as a string, as stored in the connection attribute; empty
 * means the password is stored only.
 */
angular.module('guacPam').controller('pamPlatformFieldController', ['$scope', '$injector',
        function pamPlatformFieldController($scope, $injector) {

    var $translate = $injector.get('$translate');
    var pamService = $injector.get('pamService');

    /**
     * Platforms to choose from, as {id, label} with string identifiers.
     */
    $scope.platforms = [];

    pamService.getPlatforms().then(function platformsRetrieved(platforms) {

        var options = [];
        var found = false;

        angular.forEach(platforms, function addOption(platform) {
            var id = String(platform.id);
            found = found || id === $scope.model;
            options.push({
                id    : id,
                label : platform.name + ' (' + $translate.instant('PAM.TYPE_' + platform.type.toUpperCase()) + ')'
            });
        });

        // Keep a stale assignment visible rather than silently clearing it
        if ($scope.model && !found)
            options.push({ id : $scope.model, label : '#' + $scope.model + ' (missing)' });

        $scope.platforms = options;

    });

}]);
