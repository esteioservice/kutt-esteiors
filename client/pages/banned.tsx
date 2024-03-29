import getConfig from "next/config";
import Link from "next/link";
import React from "react";

import AppWrapper from "../components/AppWrapper";
import { H2, H4, Span } from "../components/Text";
import Footer from "../components/Footer";
import ALink from "../components/ALink";
import { Col } from "../components/Layout";

const { publicRuntimeConfig } = getConfig();

const BannedPage = () => {
  return (
    <AppWrapper>
      <Col flex="1 1 100%" alignItems="center">
        <H2 textAlign="center" my={3} normal>
          O link foi banido e removido por causa de{" "}
          <Span style={{ borderBottom: "1px dotted rgba(0, 0, 0, 0.4)" }} bold>
            malware or scam
          </Span>
          .
        </H2>
        <H4 textAlign="center" normal>
          Se você notou um link de malware/scam encurtado por{" "}
          {publicRuntimeConfig.SITE_NAME},{" "}
          <Link href="/report">
            <ALink title="Envie um Relatório">envie-nos um relatório</ALink>
          </Link>
          .
        </H4>
      </Col>
      <Footer />
    </AppWrapper>
  );
};

export default BannedPage;
