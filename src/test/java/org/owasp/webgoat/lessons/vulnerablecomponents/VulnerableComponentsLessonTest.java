/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.StreamException;
import com.thoughtworks.xstream.security.ForbiddenClassException;
import org.junit.jupiter.api.Test;

public class VulnerableComponentsLessonTest {

  String strangeContact =
      "<contact class='dynamic-proxy'>\n"
          + "<interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>\n"
          + "  <handler class='java.beans.EventHandler'>\n"
          + "    <target class='java.lang.ProcessBuilder'>\n"
          + "      <command>\n"
          + "        <string>calc.exe</string>\n"
          + "      </command>\n"
          + "    </target>\n"
          + "    <action>start</action>\n"
          + "  </handler>\n"
          + "</contact>";
  String contact = "<contact>\n" + "</contact>";

  @Test
  public void testTransformation() throws Exception {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    assertThat(xstream.fromXML(contact)).isNotNull();
  }

  /**
   * XStream 1.4.21 enables security restrictions by default and blocks dangerous class
   * deserialization (CVE-2013-7285). Attempting to unmarshal a payload that uses dynamic-proxy
   * with java.beans.EventHandler / java.lang.ProcessBuilder now throws ForbiddenClassException
   * instead of silently executing arbitrary code.
   */
  @Test
  public void testIllegalTransformation() throws Exception {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    // In XStream >= 1.4.7 the security framework blocks unsafe types by default.
    // The exploit payload must be rejected with a ForbiddenClassException.
    assertThrows(
        ForbiddenClassException.class,
        () -> ((Contact) xstream.fromXML(strangeContact)).getFirstName());
  }

  @Test
  public void testIllegalPayload() throws Exception {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    Exception e =
        assertThrows(
            StreamException.class, () -> ((Contact) xstream.fromXML("bullssjfs")).getFirstName());
    assertThat(e.getCause().getMessage().contains("START_DOCUMENT")).isTrue();
  }
}
