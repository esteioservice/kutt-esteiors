import getConfig from "next/config";
import React from "react";

import AppWrapper from "../components/AppWrapper";
import { Col } from "../components/Layout";

const { publicRuntimeConfig } = getConfig();

const ProjetoPage = () => (
  <AppWrapper>
    {/* TODO: better container */}
    <Col width={600} maxWidth="97%" alignItems="flex-start">
      <h3>{publicRuntimeConfig.SITE_NAME} Termos do Serviço</h3>
      <p>
        Acessando o site em{" "}
        <a href={`https://${publicRuntimeConfig.DEFAULT_DOMAIN}`}>
          https://{publicRuntimeConfig.DEFAULT_DOMAIN}
        </a>
        , você concorda em obedecer a estes termos de serviço, todos aplicáveis
        leis e regulamentos e concorda que é responsável pela conformidade
        com quaisquer leis locais aplicáveis. Se você não concorda com qualquer um destes
        termos, você está proibido de usar ou acessar este site. o
        materiais contidos neste site são protegidos por
        direito autoral e direito de marca registrada.
      </p>
      <p>
        Em nenhum caso {publicRuntimeConfig.SITE_NAME} ou seus fornecedores sejam
        responsável por quaisquer danos (incluindo, sem limitação, danos por perda
        de dados ou lucro, ou devido à interrupção de negócios) decorrentes do
        uso ou incapacidade de usar os materiais em{" "}
        {publicRuntimeConfig.DEFAULT_DOMAIN} website, mesmo que{" "}
        {publicRuntimeConfig.SITE_NAME} ou um {publicRuntimeConfig.SITE_NAME}{" "}
        representante autorizado foi notificado oralmente ou por escrito do
        possibilidade de tal dano. Porque algumas jurisdições não permitem
        limitações nas garantias implícitas ou limitações de responsabilidade para
        danos conseqüentes ou incidentais, essas limitações podem não se aplicar a
        tu.
      </p>
      <p>
        Os materiais que aparecem em {publicRuntimeConfig.SITE_NAME} website poderia
        incluem erros técnicos, tipográficos ou fotográficos.{" "}
        {publicRuntimeConfig.SITE_NAME} não garante que qualquer um dos
        os materiais em seu site são precisos, completos ou atuais.{" "}
        {publicRuntimeConfig.SITE_NAME} pode fazer alterações nos materiais
        contidos em seu site a qualquer momento sem aviso prévio. Contudo{" "}
        {publicRuntimeConfig.SITE_NAME} não se compromete a atualizar
        os materiais.
      </p>
      <p>
        {publicRuntimeConfig.SITE_NAME} não revisou todos os sites vinculados
        ao seu site e não é responsável pelo conteúdo de tais
        site vinculado. A inclusão de qualquer link não implica endosso por{" "}
        {publicRuntimeConfig.SITE_NAME} do site. Uso de qualquer um desses links
        o site está no {"user's"} o próprio risco.
      </p>
      <p>
        {publicRuntimeConfig.SITE_NAME} pode revisar estes termos de serviço para
        seu site a qualquer momento sem aviso prévio. Ao usar este site você está
        concordando em se comprometer com a versão então atual destes termos de
        serviço.
      </p>
    </Col>
  </AppWrapper>
);

export default ProjetoPage;
