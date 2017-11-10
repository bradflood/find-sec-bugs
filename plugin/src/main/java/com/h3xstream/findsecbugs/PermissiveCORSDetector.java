/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs;

import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import com.h3xstream.findsecbugs.injection.BasicInjectionDetector;
import com.h3xstream.findsecbugs.injection.InjectionPoint;
import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.Taint.State;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class PermissiveCORSDetector extends BasicInjectionDetector {

    private static final String PERMISSIVE_CORS = "PERMISSIVE_CORS";
    private static final String HTTP_SERVLET_RESPONSE_CLASS = "javax.servlet.http.HttpServletResponse";
    private static final String HEADER_KEY = "Access-Control-Allow-Origin";

    private static final InvokeMatcherBuilder SERVLET_RESPONSE_ADD_HEADER_METHOD = invokeInstruction()
            .atClass(HTTP_SERVLET_RESPONSE_CLASS).atMethod("addHeader")
            .withArgs("(Ljava/lang/String;Ljava/lang/String;)V");

    private static final InvokeMatcherBuilder SERVLET_RESPONSE_SET_HEADER_METHOD = invokeInstruction()
            .atClass(HTTP_SERVLET_RESPONSE_CLASS).atMethod("setHeader")
            .withArgs("(Ljava/lang/String;Ljava/lang/String;)V");

    public PermissiveCORSDetector(BugReporter bugReporter) {
        super(bugReporter);
    }

    @Override
    protected InjectionPoint getInjectionPoint(InvokeInstruction invoke, ConstantPoolGen cpg,
            InstructionHandle handle) {
        assert invoke != null && cpg != null;

        if (SERVLET_RESPONSE_ADD_HEADER_METHOD.matches(invoke, cpg)) {
            return new InjectionPoint(new int[] { 0 }, PERMISSIVE_CORS);
        }

        if (SERVLET_RESPONSE_SET_HEADER_METHOD.matches(invoke, cpg)) {
            return new InjectionPoint(new int[] { 0 }, PERMISSIVE_CORS);
        }
        return InjectionPoint.NONE;
    }

    @Override
    protected int getPriorityFromTaintFrame(TaintFrame fact, int offset) throws DataflowAnalysisException {
        // Get the value of the Access-Control-Allow-Origin parameter
        Taint headerKeyTaint = fact.getStackValue(1);
        if (!(HEADER_KEY.equalsIgnoreCase(headerKeyTaint.getConstantValue()))) {
            return Priorities.IGNORE_PRIORITY;
        }

        Taint headerValueTaint = fact.getStackValue(0);
        if (State.TAINTED.equals(headerValueTaint.getState())) {
            return Priorities.HIGH_PRIORITY;
        }

        String headerValue = headerValueTaint.getConstantOrPotentialValue();
        if (headerValue == null) {
            return Priorities.IGNORE_PRIORITY;
        }

        if (headerValue.contains("*") || "null".equalsIgnoreCase(headerValue)) {
            return Priorities.HIGH_PRIORITY;
        }

        // Taint valueTaint = fact.getStackValue(0);
        // Taint parameterTaint = fact.getStackValue(1);
        //
        // // ignore if it is a constant
        // if (valueTaint.getConstantValue() != null ) {
        // return Priorities.IGNORE_PRIORITY;
        // }
        //
        return Priorities.IGNORE_PRIORITY;
    }
}
