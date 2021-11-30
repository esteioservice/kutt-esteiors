import React from "react";
import styled from "styled-components";
import { Flex } from "reflexbox/styled-components";

import FeaturesItem from "./FeaturesItem";
import { ColCenterH } from "./Layout";
import { Colors } from "../consts";
import Text, { H3 } from "./Text";

const Features = () => (
  <ColCenterH
    width={1}
    flex="0 0 auto"
    py={[64, 100]}
    backgroundColor={Colors.FeaturesBg}
  >
    <H3 fontSize={[26, 28]} mb={72} light>
      Recusros de ponta.
    </H3>
    <Flex
      width={1200}
      maxWidth="100%"
      flex="1 1 auto"
      justifyContent="center"
      flexWrap={["wrap", "wrap", "wrap", "nowrap"]}
    >
      <FeaturesItem title="Gerenciando links" icon="edit">
        Crie, proteja e exclua seus links e monitore-os com detalhes
        Estatisticas..
      </FeaturesItem>
      <FeaturesItem title="API" icon="zap">
        Use a API fornecida para criar, excluir e obter URLs de qualquer lugar.
      </FeaturesItem>
      <FeaturesItem title="Totalmente Grátis" icon="heart">
        Este projeto é totalmente gratuito para uso dos Escoteiros RS.
      </FeaturesItem>
    </Flex>
  </ColCenterH>
);

export default Features;
