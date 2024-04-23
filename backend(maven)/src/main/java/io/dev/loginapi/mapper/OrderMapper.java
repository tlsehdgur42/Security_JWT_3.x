package io.dev.loginapi.mapper;

import io.dev.loginapi.model.Order;
import io.dev.loginapi.rest.dto.CreateOrderRequest;
import io.dev.loginapi.rest.dto.OrderDto;

public interface OrderMapper {

    Order toOrder(CreateOrderRequest createOrderRequest);

    OrderDto toOrderDto(Order order);
}