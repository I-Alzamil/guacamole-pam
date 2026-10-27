/**
 * "Email notifications" section of the Preferences tab: which emails the
 * user wants, among those they can receive: everything PAM does for
 * administrators, requests awaiting their approval for approvers, and
 * their own requests and access for everyone. Shown only while emails are
 * sent, with the address they go to. Placed after the badges by
 * templates/pamPreferencesPatch.html.
 */
angular.module('guacPam').directive('pamEmailPreferencesSection', [function pamEmailPreferencesSection() {

    return {
        restrict   : 'E',
        scope      : {},
        template   : '<div ng-show="emails.enabled">'
                   + '<h2 class="header">{{ \'PAM.SECTION_HEADER_EMAILS\' | translate }}</h2>'
                   + '<div class="settings section pam-emails">'
                   + '<p ng-if="emails.address">{{ \'PAM.HELP_EMAILS\' | translate:{ ADDRESS : emails.address } }}</p>'
                   + '<p ng-if="!emails.address" class="pam-settings-notice">{{ \'PAM.HELP_EMAILS_NO_ADDRESS\' | translate }}</p>'
                   + '<div class="form"><table class="fields">'
                   + '<tr ng-repeat="kind in kinds" ng-show="isAvailable(kind)">'
                   + '<th><label for="pam-email-{{ kind }}">{{ \'PAM.FIELD_HEADER_EMAIL_\' + (kind | uppercase) | translate }}</label></th>'
                   + '<td><input id="pam-email-{{ kind }}" type="checkbox" ng-model="choices[kind]"'
                   + '       ng-change="save(kind)" ng-disabled="saving[kind]"></td>'
                   + '</tr>'
                   + '</table></div>'
                   + '</div>'
                   + '</div>',
        controller : ['$scope', '$injector', function pamEmailPreferencesSectionController($scope, $injector) {

            var guacNotification = $injector.get('guacNotification');
            var pamService       = $injector.get('pamService');

            $scope.kinds = ['everything', 'approvals', 'own'];

            /**
             * Whether emails are sent, the user's address, and which kinds
             * they want.
             */
            $scope.emails = {};

            /**
             * Who the user is: "administrator" and "approver".
             */
            var access = {};

            /**
             * The checkboxes' models.
             */
            $scope.choices = {};

            $scope.saving = {};

            pamService.getAccess().then(function accessRetrieved(retrieved) {
                access = retrieved;
                $scope.emails = retrieved.emails || {};
                angular.forEach($scope.kinds, function copyChoice(kind) {
                    $scope.choices[kind] = !$scope.emails.wanted || $scope.emails.wanted[kind] !== false;
                });
            }, angular.noop);

            $scope.isAvailable = function isAvailable(kind) {
                if (kind === 'everything')
                    return !!access.administrator;
                if (kind === 'approvals')
                    return !!access.approver;
                return true;
            };

            $scope.save = function save(kind) {
                var wanted = $scope.choices[kind];
                $scope.saving[kind] = true;
                pamService.setEmailWanted(kind, wanted)['catch'](function saveFailed(error) {
                    $scope.choices[kind] = !wanted;
                    guacNotification.SHOW_REQUEST_ERROR(error);
                })['finally'](function saved() {
                    delete $scope.saving[kind];
                });
            };

        }]
    };

}]);
