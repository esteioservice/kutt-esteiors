import { useFormState } from "react-use-form-state";
import { Flex } from "reflexbox/styled-components";
import React, { useState } from "react";
import axios from "axios";

import Text, { H2, Span } from "../components/Text";
import AppWrapper from "../components/AppWrapper";
import { TextInput } from "../components/Input";
import { Button } from "../components/Button";
import { Col } from "../components/Layout";
import Icon from "../components/Icon";
import { useMessage } from "../hooks";
import { APIv2 } from "../consts";

import getConfig from "next/config";

const { publicRuntimeConfig } = getConfig();

const ReportPage = () => {
  const [formState, { text }] = useFormState<{ url: string }>();
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useMessage(5000);

  const onSubmit = async e => {
    e.preventDefault();
    setLoading(true);
    setMessage();
    try {
      await axios.post(`${APIv2.Links}/report`, { link: formState.values.url });
      setMessage("Obrigado pelo relatório, tomaremos medidas em breve.", "green");
      formState.clear();
    } catch (error) {
      setMessage(error?.response?.data?.error || "Não foi possível enviar relatório.");
    }

    setLoading(false);
  };

  return (
    <AppWrapper>
      <Col width={600} maxWidth="97%" alignItems="flex-start">
        <H2 my={3} bold>
          Reportar abuso
        </H2>
        <Text mb={3}>
          Denuncie abusos, malware e links de phishing para o endereço de e-mail abaixo
          ou use o formulário. Tomaremos medidas em breve.
        </Text>
        <Text mb={4}>
          {(publicRuntimeConfig.REPORT_EMAIL || "").replace("@", "[at]")}
        </Text>
        <Text mb={3}>
          <Span bold>URL contendo malware/scam:</Span>
        </Text>
        <Flex
          as="form"
          flexDirection={["column", "row"]}
          alignItems={["flex-start", "center"]}
          justifyContent="flex-start"
          onSubmit={onSubmit}
        >
          <TextInput
            {...text("url")}
            placeholder={`${publicRuntimeConfig.DEFAULT_DOMAIN}/example`}
            height={[44, 74]}
            width={[1, 1 / 2]}
            flex="0 0 auto"
            mr={3}
            required
          />
          <Button type="submit" flex="0 0 auto" height={[40, 44]} mt={[3, 0]}>
            {loading && <Icon name={"spinner"} stroke="white" mr={2} />}
            Enviar
          </Button>
        </Flex>
        <Text fontSize={14} mt={3} color={message.color}>
          {message.text}
        </Text>
      </Col>
    </AppWrapper>
  );
};

export default ReportPage;
