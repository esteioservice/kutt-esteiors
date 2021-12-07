import getConfig from "next/config";
import React from "react";

import AppWrapper from "../components/AppWrapper";
import { Col } from "../components/Layout";

const { publicRuntimeConfig } = getConfig();

const ProjetoPage = () => (
  <AppWrapper>
    {/* TODO: better container */}
    <Col width={600} maxWidth="97%" alignItems="flex-start">
      <h3>Projeto Encurtador de Links {publicRuntimeConfig.SITE_NAME} </h3>
      <p>
        Acessando o site em{" "}
        <a href={`https://${publicRuntimeConfig.DEFAULT_DOMAIN}`}>
          https://{publicRuntimeConfig.DEFAULT_DOMAIN}
        </a>
        , Você terá acesso ao site de encurtador de links próprios para grupos escoteiros
        realizarem seus links de forma personalizada.
        Este projeto tem a finalidade de tornar a divulgação do movimento escoteiro nas UELs
        mais fácil e dinâmica.
      </p>
      <p>
        O Projeto {publicRuntimeConfig.SITE_NAME}.RS é uma ferramenta totalmente gratuita,
        fazendo com que possa divulgar os seus links de forma mais profissional.
      </p>
    </Col>
  </AppWrapper>
);

export default ProjetoPage;
