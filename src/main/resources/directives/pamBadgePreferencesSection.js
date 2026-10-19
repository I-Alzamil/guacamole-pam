/**
 * "Notification badges" section of the Preferences tab: which badges the
 * user wants, among those they can have. Hidden for users who can have
 * none. Placed after the appearance settings by
 * templates/pamBadgePreferencesPatch.html.
 */
angular.module('guacPam').directive('pamBadgePreferencesSection', [function pamBadgePreferencesSection() {

    return {
        restrict   : 'E',
        scope      : {},
        template   : '<div ng-show="isAvailable(\'approvals\') || isAvailable(\'rotations\')">'
                   + '<h2 class="header">{{ \'PAM.SECTION_HEADER_BADGES\' | translate }}</h2>'
                   + '<div class="settings section pam-badges">'
                   + '<p>{{ \'PAM.HELP_BADGES\' | translate }}</p>'
                   + '<div class="form"><table class="fields">'
                   + '<tr ng-repeat="badge in badges" ng-show="isAvailable(badge)">'
                   + '<th><label for="pam-badge-{{ badge }}">{{ \'PAM.FIELD_HEADER_BADGE_\' + (badge | uppercase) | translate }}</label></th>'
                   + '<td><input id="pam-badge-{{ badge }}" type="checkbox" ng-model="choices[badge]"'
                   + '       ng-change="save(badge)" ng-disabled="state.saving[badge]"></td>'
                   + '</tr>'
                   + '</table></div>'
                   + '</div>'
                   + '</div>',
        controller : ['$scope', '$injector', function pamBadgePreferencesSectionController($scope, $injector) {

            var guacNotification    = $injector.get('guacNotification');
            var pamBadgePreferences = $injector.get('pamBadgePreferences');

            $scope.badges = ['approvals', 'rotations'];

            $scope.state = pamBadgePreferences.state;

            /**
             * The checkboxes' own models, following the shared choices.
             */
            $scope.choices = {};

            $scope.$watchCollection('state.shown', function choicesChanged(shown) {
                angular.forEach($scope.badges, function copyChoice(badge) {
                    $scope.choices[badge] = shown[badge] !== false;
                });
            });

            $scope.isAvailable = function isAvailable(badge) {
                return $scope.state.loaded && !!$scope.state.available[badge];
            };

            $scope.save = function save(badge) {
                pamBadgePreferences.set(badge, $scope.choices[badge])
                ['catch'](guacNotification.SHOW_REQUEST_ERROR);
            };

            if (!$scope.state.loaded)
                pamBadgePreferences.load();

        }]
    };

}]);
