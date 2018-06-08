package org.apache.taglibs.standard.tag.common.core;

import javax.servlet.jsp.JspTagException;
import javax.servlet.jsp.jstl.core.LoopTagSupport;
public abstract class ForEachSupport extends LoopTagSupport {

    @Override
    protected void prepare() throws JspTagException {
    }


    @Override
    protected boolean hasNext() throws JspTagException {
        return items.hasNext();
    }

    @Override
    protected Object next() throws JspTagException {
        return items.next();
    }

    @Override
    public void release() {
    }


}