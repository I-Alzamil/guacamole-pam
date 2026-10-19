package org.apache.guacamole.pam.ssh;

import java.util.List;

/**
 * Result of validating a sequence script, as returned by the REST API.
 */
public class ValidationResult {

    private final List<SequenceScript.ParseError> errors;

    private final int stepCount;

    public ValidationResult(SequenceScript script) {
        this.errors = script.getErrors();
        this.stepCount = script.getSteps().size();
    }

    public List<SequenceScript.ParseError> getErrors() {
        return errors;
    }

    public int getStepCount() {
        return stepCount;
    }

}
