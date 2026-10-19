/**
 * "Approve" checkbox next to a connection or connection group of the
 * connections list in the user and user group editors, shown while the
 * user or group being edited has "Can approve requests". Placed by
 * templates/pamApproveChoiceConnection.html and
 * templates/pamApproveChoiceGroup.html.
 */
angular.module('guacPam').directive('pamApproveChoice', [function pamApproveChoice() {

    return {
        restrict    : 'E',
        scope       : {
            item : '<',
            kind : '@'
        },
        template    : '<label class="pam-approve-choice" ng-if="selection.isApprover()"'
                    + '       title="{{ (kind === \'group\' ? \'PAM_APPROVAL_PERMISSIONS.HELP_APPROVE_GROUP\''
                    + '                                    : \'PAM_APPROVAL_PERMISSIONS.HELP_APPROVE_CONNECTION\') | translate }}">'
                    + '<input type="checkbox" ng-model="selected" ng-model-options="{ getterSetter: true }"'
                    + '       ng-disabled="!selection.isEditable()">'
                    + '{{ \'PAM_APPROVAL_PERMISSIONS.FIELD_APPROVE\' | translate }}'
                    + '</label>',
        controller  : ['$scope', '$injector', function pamApproveChoiceController($scope, $injector) {

            $scope.selection = $injector.get('pamApprovalSelection');

            $scope.selected = function selected(value) {
                if (arguments.length)
                    $scope.selection.setSelected($scope.kind, $scope.item.identifier, value);
                return $scope.selection.isSelected($scope.kind, $scope.item.identifier);
            };

        }]
    };

}]);
