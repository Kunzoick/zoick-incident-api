package com.zoick.incidentapi.dto.response;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.domain.Page;

import java.util.List;
import java.util.function.Function;

/**
 * standard response shape for paged results used for every list endpoint in the system
 * per blueprint contract, default pageSize= 20, maxPageSize= 100
 */
@Getter
@Builder
public class PagedResponse<T> {
    private List<T> data;
    private int page;
    private int pageSize;
    private long totalElements;
    private int totalPages;
    //maps a spring data page for our pagedResponse shape, mapper function converts domain objects to response objects
    public static <T, R> PagedResponse<R> from(Page<T> page,  Function<T, R> mapper){
        return PagedResponse.<R>builder().data(page.getContent().stream().map(mapper).toList())
                .page(page.getNumber() + 1)
                .pageSize(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .build();
    }
}
