package com.innowise.authservice.core.mapper;

import java.util.List;
import org.mapstruct.Builder;
import org.mapstruct.MapperConfig;
import org.mapstruct.MappingTarget;
import org.mapstruct.NullValueMappingStrategy;
import org.mapstruct.NullValuePropertyMappingStrategy;
import org.mapstruct.ReportingPolicy;

@MapperConfig(
    componentModel = "spring",
    builder = @Builder(disableBuilder = true),
    // Игнорировать непокрытые поля
    unmappedTargetPolicy = ReportingPolicy.IGNORE,
    // Если в DTO пришло поле == null, НЕ маппить его в Entity.
    nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE,
    // Если маппим null-коллекцию, вернуть пустую коллекцию, а не null
    nullValueIterableMappingStrategy = NullValueMappingStrategy.RETURN_DEFAULT
)
public interface BaseMapper<E, D> {

    D toDto(E e);

    E toEntity(D d);

    List<D> toDtos(Iterable<E> list);

    List<E> toEntities(Iterable<D> list);

    E merge(@MappingTarget E entity, D dto);
}
