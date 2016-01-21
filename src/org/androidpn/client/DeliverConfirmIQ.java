package org.androidpn.client;

import org.jivesoftware.smack.packet.IQ;

public class DeliverConfirmIQ extends IQ {

	private String uudi;

	public String getUudi() {
		return uudi;
	}

	public void setUudi(String uudi) {
		this.uudi = uudi;
	}

	@Override
	public String getChildElementXML() {
		StringBuilder buf = new StringBuilder();
        buf.append("<").append("deliverconfirm").append(" xmlns=\"").append(
                "androidpn:iq:deliverconfirm").append("\">");
        if (uudi != null) {
            buf.append("<uudi>").append(uudi).append("</uudi>");
        }
        buf.append("</").append("deliverconfirm").append("> ");
        return buf.toString();
	}
}
