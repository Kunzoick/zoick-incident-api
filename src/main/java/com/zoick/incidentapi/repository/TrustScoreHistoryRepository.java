package com.zoick.incidentapi.repository;

import com.zoick.incidentapi.domain.TrustScoreHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
@Repository
public interface TrustScoreHistoryRepository extends JpaRepository<TrustScoreHistory, String>{
    Page<TrustScoreHistory> findByUserIdOrderByChangedAtDesc(
            String userId, Pageable pageable);
}
